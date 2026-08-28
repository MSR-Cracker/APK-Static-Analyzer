"""Multi-DEX binary parser with a full Dalvik bytecode disassembler and cross-reference engine."""

import struct
import re
import os
import zipfile
import logging
from typing import List, Dict, Any, Tuple, Optional, Set

from analyzer.models import (
    DexMethod,
    InstructionDetail,
    DexFileInfo,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LEB128 helpers
# ---------------------------------------------------------------------------

def read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Reads an unsigned LEB128 integer and returns (value, new_offset)."""
    result = 0
    shift = 0
    cur = offset

    while True:
        if cur >= len(data):
            return result, cur

        byte = data[cur]
        cur += 1

        result |= (byte & 0x7F) << shift

        if not (byte & 0x80):
            break

        shift += 7

        # Defensive protection against malformed/corrupt input.
        if shift > 70:
            return result, cur

    return result, cur


def read_sleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Reads a signed LEB128 integer and returns (value, new_offset)."""
    result = 0
    shift = 0
    cur = offset
    byte = 0

    while True:
        if cur >= len(data):
            return result, cur

        byte = data[cur]
        cur += 1

        result |= (byte & 0x7F) << shift
        shift += 7

        if not (byte & 0x80):
            break

        if shift > 70:
            return result, cur

    if (byte & 0x40) and shift < 64:
        result |= -(1 << shift)

    return result, cur


# ---------------------------------------------------------------------------
# Dalvik type helpers
# ---------------------------------------------------------------------------

def parse_type_descriptor(desc: str) -> str:
    """Converts Dalvik type descriptor to human-readable type."""
    if not desc:
        return "void"

    if desc == "V":
        return "void"
    if desc == "Z":
        return "boolean"
    if desc == "B":
        return "byte"
    if desc == "S":
        return "short"
    if desc == "C":
        return "char"
    if desc == "I":
        return "int"
    if desc == "J":
        return "long"
    if desc == "F":
        return "float"
    if desc == "D":
        return "double"

    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")

    if desc.startswith("["):
        return parse_type_descriptor(desc[1:]) + "[]"

    return desc.replace("/", ".")


# ---------------------------------------------------------------------------
# Complete Dalvik Opcode Specification Table
# (opcode_hex, name, format, length_in_bytes)
# ---------------------------------------------------------------------------

OPCODE_INFO: Dict[int, Tuple[str, str, int]] = {
    0x00: ("nop", "10x", 2),
    0x01: ("move", "12x", 2),
    0x02: ("move/from16", "22x", 4),
    0x03: ("move/16", "32x", 6),
    0x04: ("move-wide", "12x", 2),
    0x05: ("move-wide/from16", "22x", 4),
    0x06: ("move-wide/16", "32x", 6),
    0x07: ("move-object", "12x", 2),
    0x08: ("move-object/from16", "22x", 4),
    0x09: ("move-object/16", "32x", 6),

    0x0A: ("move-result", "11x", 2),
    0x0B: ("move-result-wide", "11x", 2),
    0x0C: ("move-result-object", "11x", 2),
    0x0D: ("move-exception", "11x", 2),

    0x0E: ("return-void", "10x", 2),
    0x0F: ("return", "11x", 2),
    0x10: ("return-wide", "11x", 2),
    0x11: ("return-object", "11x", 2),

    0x12: ("const/4", "11n", 2),
    0x13: ("const/16", "21s", 4),
    0x14: ("const", "31i", 6),
    0x15: ("const/high16", "21h", 4),
    0x16: ("const-wide/16", "21s", 4),
    0x17: ("const-wide/32", "31i", 6),
    0x18: ("const-wide", "51l", 10),
    0x19: ("const-wide/high16", "21h", 4),

    0x1A: ("const-string", "21c", 4),
    0x1B: ("const-string/jumbo", "31c", 6),
    0x1C: ("const-class", "21c", 4),

    0x1D: ("monitor-enter", "11x", 2),
    0x1E: ("monitor-exit", "11x", 2),

    0x1F: ("check-cast", "21c", 4),
    0x20: ("instance-of", "22c", 4),
    0x21: ("array-length", "12x", 2),
    0x22: ("new-instance", "21c", 4),
    0x23: ("new-array", "22c", 4),
    0x24: ("filled-new-array", "35c", 6),
    0x25: ("filled-new-array/range", "3rc", 6),
    0x26: ("fill-array-data", "31t", 6),
    0x27: ("throw", "11x", 2),

    0x28: ("goto", "10t", 2),
    0x29: ("goto/16", "20t", 4),
    0x2A: ("goto/32", "30t", 6),
    0x2B: ("packed-switch", "31t", 6),
    0x2C: ("sparse-switch", "31t", 6),

    0x2D: ("cmpl-float", "23x", 4),
    0x2E: ("cmpg-float", "23x", 4),
    0x2F: ("cmpl-double", "23x", 4),
    0x30: ("cmpg-double", "23x", 4),
    0x31: ("cmp-long", "23x", 4),

    0x32: ("if-eq", "22t", 4),
    0x33: ("if-ne", "22t", 4),
    0x34: ("if-lt", "22t", 4),
    0x35: ("if-ge", "22t", 4),
    0x36: ("if-gt", "22t", 4),
    0x37: ("if-le", "22t", 4),

    0x38: ("if-eqz", "21t", 4),
    0x39: ("if-nez", "21t", 4),
    0x3A: ("if-ltz", "21t", 4),
    0x3B: ("if-gez", "21t", 4),
    0x3C: ("if-gtz", "21t", 4),
    0x3D: ("if-lez", "21t", 4),

    0x44: ("aget", "23x", 4),
    0x45: ("aget-wide", "23x", 4),
    0x46: ("aget-object", "23x", 4),
    0x47: ("aget-boolean", "23x", 4),
    0x48: ("aget-byte", "23x", 4),
    0x49: ("aget-char", "23x", 4),
    0x4A: ("aget-short", "23x", 4),

    0x4B: ("aput", "23x", 4),
    0x4C: ("aput-wide", "23x", 4),
    0x4D: ("aput-object", "23x", 4),
    0x4E: ("aput-boolean", "23x", 4),
    0x4F: ("aput-byte", "23x", 4),
    0x50: ("aput-char", "23x", 4),
    0x51: ("aput-short", "23x", 4),

    0x52: ("iget", "22c", 4),
    0x53: ("iget-wide", "22c", 4),
    0x54: ("iget-object", "22c", 4),
    0x55: ("iget-boolean", "22c", 4),
    0x56: ("iget-byte", "22c", 4),
    0x57: ("iget-char", "22c", 4),
    0x58: ("iget-short", "22c", 4),

    0x59: ("iput", "22c", 4),
    0x5A: ("iput-wide", "22c", 4),
    0x5B: ("iput-object", "22c", 4),
    0x5C: ("iput-boolean", "22c", 4),
    0x5D: ("iput-byte", "22c", 4),
    0x5E: ("iput-char", "22c", 4),
    0x5F: ("iput-short", "22c", 4),

    0x60: ("sget", "21c", 4),
    0x61: ("sget-wide", "21c", 4),
    0x62: ("sget-object", "21c", 4),
    0x63: ("sget-boolean", "21c", 4),
    0x64: ("sget-byte", "21c", 4),
    0x65: ("sget-char", "21c", 4),
    0x66: ("sget-short", "21c", 4),

    0x67: ("sput", "21c", 4),
    0x68: ("sput-wide", "21c", 4),
    0x69: ("sput-object", "21c", 4),
    0x6A: ("sput-boolean", "21c", 4),
    0x6B: ("sput-byte", "21c", 4),
    0x6C: ("sput-char", "21c", 4),
    0x6D: ("sput-short", "21c", 4),

    0x6E: ("invoke-virtual", "35c", 6),
    0x6F: ("invoke-super", "35c", 6),
    0x70: ("invoke-direct", "35c", 6),
    0x71: ("invoke-static", "35c", 6),
    0x72: ("invoke-interface", "35c", 6),

    0x74: ("invoke-virtual/range", "3rc", 6),
    0x75: ("invoke-super/range", "3rc", 6),
    0x76: ("invoke-direct/range", "3rc", 6),
    0x77: ("invoke-static/range", "3rc", 6),
    0x78: ("invoke-interface/range", "3rc", 6),

    0x7B: ("neg-int", "12x", 2),
    0x7C: ("not-int", "12x", 2),
    0x7D: ("neg-long", "12x", 2),
    0x7E: ("not-long", "12x", 2),
    0x7F: ("neg-float", "12x", 2),
    0x80: ("neg-double", "12x", 2),
    0x81: ("int-to-long", "12x", 2),
    0x82: ("int-to-float", "12x", 2),
    0x83: ("int-to-double", "12x", 2),
    0x84: ("long-to-int", "12x", 2),
    0x85: ("long-to-float", "12x", 2),
    0x86: ("long-to-double", "12x", 2),
    0x87: ("float-to-int", "12x", 2),
    0x88: ("float-to-long", "12x", 2),
    0x89: ("float-to-double", "12x", 2),
    0x8A: ("double-to-int", "12x", 2),
    0x8B: ("double-to-long", "12x", 2),
    0x8C: ("double-to-float", "12x", 2),
    0x8D: ("int-to-byte", "12x", 2),
    0x8E: ("int-to-char", "12x", 2),
    0x8F: ("int-to-short", "12x", 2),

    0x90: ("add-int", "23x", 4),
    0x91: ("sub-int", "23x", 4),
    0x92: ("mul-int", "23x", 4),
    0x93: ("div-int", "23x", 4),
    0x94: ("rem-int", "23x", 4),
    0x95: ("and-int", "23x", 4),
    0x96: ("or-int", "23x", 4),
    0x97: ("xor-int", "23x", 4),
    0x98: ("shl-int", "23x", 4),
    0x99: ("shr-int", "23x", 4),
    0x9A: ("ushr-int", "23x", 4),

    0xB0: ("add-int/2addr", "12x", 2),
    0xB1: ("sub-int/2addr", "12x", 2),
    0xB2: ("mul-int/2addr", "12x", 2),
    0xB3: ("div-int/2addr", "12x", 2),
    0xB4: ("rem-int/2addr", "12x", 2),
    0xB5: ("and-int/2addr", "12x", 2),
    0xB6: ("or-int/2addr", "12x", 2),
    0xB7: ("xor-int/2addr", "12x", 2),
    0xB8: ("shl-int/2addr", "12x", 2),
    0xB9: ("shr-int/2addr", "12x", 2),
    0xBA: ("ushr-int/2addr", "12x", 2),

    0xD0: ("add-int/lit16", "22s", 4),
    0xD1: ("rsub-int", "22s", 4),
    0xD2: ("mul-int/lit16", "22s", 4),
    0xD3: ("div-int/lit16", "22s", 4),
    0xD4: ("rem-int/lit16", "22s", 4),
    0xD5: ("and-int/lit16", "22s", 4),
    0xD6: ("or-int/lit16", "22s", 4),
    0xD7: ("xor-int/lit16", "22s", 4),

    0xD8: ("add-int/lit8", "22b", 4),
    0xD9: ("rsub-int/lit8", "22b", 4),
    0xDA: ("mul-int/lit8", "22b", 4),
    0xDB: ("div-int/lit8", "22b", 4),
    0xDC: ("rem-int/lit8", "22b", 4),
    0xDD: ("and-int/lit8", "22b", 4),
    0xDE: ("or-int/lit8", "22b", 4),
    0xDF: ("xor-int/lit8", "22b", 4),
    0xE0: ("shl-int/lit8", "22b", 4),
    0xE1: ("shr-int/lit8", "22b", 4),
    0xE2: ("ushr-int/lit8", "22b", 4),

    0xFA: ("invoke-polymorphic", "35c", 6),
    0xFB: ("invoke-polymorphic/range", "3rc", 6),
    0xFC: ("invoke-custom", "35c", 6),
    0xFD: ("invoke-custom/range", "3rc", 6),
}


# ---------------------------------------------------------------------------
# DEX parser
# ---------------------------------------------------------------------------

class DexParser:
    """Parses a DEX binary file and disassembles Dalvik bytecode."""

    ACC_PUBLIC = 0x1
    ACC_PRIVATE = 0x2
    ACC_PROTECTED = 0x4
    ACC_STATIC = 0x8
    ACC_FINAL = 0x10
    ACC_SYNCHRONIZED = 0x20
    ACC_NATIVE = 0x100
    ACC_INTERFACE = 0x200
    ACC_ABSTRACT = 0x400
    ACC_CONSTRUCTOR = 0x10000

    PURCHASE_KEYWORDS = (
        "purchase",
        "purchased",
        "subscription",
        "subscribe",
        "subscribed",
        "billing",
        "payment",
        "pay",
        "premium",
        "entitlement",
        "license",
        "receipt",
        "checkout",
        "order",
        "iap",
        "inapp",
    )

    URL_REGEX = re.compile(
        r"https?://[a-zA-Z0-9.-]+"
        r"(?::[0-9]+)?"
        r"(?:/[^\s\"'<>={}\\]*)?"
    )

    def __init__(
        self,
        dex_name: str,
        dex_bytes: bytes,
        source_apk: str = "base.apk",
    ):
        self.dex_name = dex_name
        self.source_apk = source_apk
        self.data = dex_bytes

        self.strings: List[str] = []
        self.type_ids: List[int] = []
        self.proto_ids: List[Tuple[int, int, int]] = []
        self.field_ids: List[Tuple[int, int, int]] = []
        self.method_ids: List[Tuple[int, int, int]] = []

        self.methods: List[DexMethod] = []

        self.class_count: int = 0
        self.method_count: int = 0

        self.unsupported_opcodes_log: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # Generic safe binary helpers
    # -----------------------------------------------------------------------

    def _has_range(self, offset: int, size: int) -> bool:
        return (
            offset >= 0
            and size >= 0
            and offset <= len(self.data)
            and offset + size <= len(self.data)
        )

    def _safe_unpack(
        self,
        fmt: str,
        offset: int,
    ) -> Optional[Tuple[Any, ...]]:
        try:
            size = struct.calcsize(fmt)
            if not self._has_range(offset, size):
                return None
            return struct.unpack_from(fmt, self.data, offset)
        except (struct.error, ValueError):
            return None

    # -----------------------------------------------------------------------
    # String decoding
    # -----------------------------------------------------------------------

    @staticmethod
    def _decode_mutf8(raw: bytes) -> str:
        """
        Decode DEX modified UTF-8 as safely as possible.

        Most APK strings are ordinary UTF-8, but DEX uses modified UTF-8.
        We explicitly handle the common encoded-NUL form C0 80 before falling
        back to Python UTF-8 decoding.
        """
        if not raw:
            return ""

        # DEX modified UTF-8 encodes U+0000 as C0 80.
        raw = raw.replace(b"\xC0\x80", b"\x00")

        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("latin-1", errors="replace")

    def _parse_string_ids(self, count: int, offset: int):
        self.strings = []

        if count <= 0:
            return

        for i in range(count):
            entry_off = offset + i * 4

            packed = self._safe_unpack_from_data("<I", entry_off)
            if packed is None:
                self.strings.append("")
                continue

            str_data_off = packed[0]

            if not self._has_range(str_data_off, 1):
                self.strings.append("")
                continue

            try:
                _, str_start = read_uleb128(self.data, str_data_off)

                if str_start > len(self.data):
                    self.strings.append("")
                    continue

                null_pos = self.data.find(b"\x00", str_start)

                if null_pos == -1:
                    self.strings.append("")
                    continue

                raw_str = self.data[str_start:null_pos]
                self.strings.append(self._decode_mutf8(raw_str))

            except Exception as exc:
                logger.debug(
                    "Failed to decode DEX string %d in %s: %s",
                    i,
                    self.dex_name,
                    exc,
                )
                self.strings.append("")

    def _safe_unpack_from_data(
        self,
        fmt: str,
        offset: int,
    ) -> Optional[Tuple[Any, ...]]:
        try:
            size = struct.calcsize(fmt)

            if (
                offset < 0
                or offset + size > len(self.data)
            ):
                return None

            return struct.unpack_from(fmt, self.data, offset)

        except (struct.error, ValueError):
            return None

    # -----------------------------------------------------------------------
    # Type / proto / field / method tables
    # -----------------------------------------------------------------------

    def _parse_type_ids(self, count: int, offset: int):
        self.type_ids = []

        for i in range(count):
            packed = self._safe_unpack_from_data(
                "<I",
                offset + i * 4,
            )

            if packed is None:
                self.type_ids.append(0)
            else:
                self.type_ids.append(packed[0])

    def _get_type_str(self, type_idx: int) -> str:
        if 0 <= type_idx < len(self.type_ids):
            str_idx = self.type_ids[type_idx]

            if 0 <= str_idx < len(self.strings):
                return self.strings[str_idx]

        return "Lunknown/Type;"

    def _parse_proto_ids(self, count: int, offset: int):
        self.proto_ids = []

        for i in range(count):
            packed = self._safe_unpack_from_data(
                "<III",
                offset + i * 12,
            )

            if packed is None:
                self.proto_ids.append((0, 0, 0))
            else:
                self.proto_ids.append(
                    (
                        packed[0],
                        packed[1],
                        packed[2],
                    )
                )

    def _get_proto_param_types(
        self,
        parameters_off: int,
    ) -> List[str]:
        if (
            parameters_off == 0
            or parameters_off >= len(self.data)
        ):
            return []

        try:
            packed = self._safe_unpack_from_data(
                "<I",
                parameters_off,
            )

            if packed is None:
                return []

            size = packed[0]

            # Defensive sanity check.
            max_possible = max(
                0,
                (len(self.data) - parameters_off - 4) // 2,
            )

            size = min(size, max_possible)

            params = []

            for i in range(size):
                packed_type = self._safe_unpack_from_data(
                    "<H",
                    parameters_off + 4 + i * 2,
                )

                if packed_type is None:
                    break

                params.append(
                    self._get_type_str(packed_type[0])
                )

            return params

        except Exception:
            return []

    def _parse_field_ids(self, count: int, offset: int):
        self.field_ids = []

        for i in range(count):
            packed = self._safe_unpack_from_data(
                "<HHI",
                offset + i * 8,
            )

            if packed is None:
                self.field_ids.append((0, 0, 0))
            else:
                self.field_ids.append(
                    (
                        packed[0],
                        packed[1],
                        packed[2],
                    )
                )

    def _get_field_info(
        self,
        field_idx: int,
    ) -> Tuple[str, str, str]:
        if not (
            0 <= field_idx < len(self.field_ids)
        ):
            return (
                "Lunknown/Class;",
                "unknownField",
                "Lunknown/Type;",
            )

        class_idx, type_idx, name_idx = (
            self.field_ids[field_idx]
        )

        c_name = parse_type_descriptor(
            self._get_type_str(class_idx)
        )

        f_type = parse_type_descriptor(
            self._get_type_str(type_idx)
        )

        f_name = (
            self.strings[name_idx]
            if 0 <= name_idx < len(self.strings)
            else "unknown"
        )

        return c_name, f_name, f_type

    def _parse_method_ids(self, count: int, offset: int):
        self.method_ids = []

        for i in range(count):
            packed = self._safe_unpack_from_data(
                "<HHI",
                offset + i * 8,
            )

            if packed is None:
                self.method_ids.append((0, 0, 0))
            else:
                self.method_ids.append(
                    (
                        packed[0],
                        packed[1],
                        packed[2],
                    )
                )

    def _get_method_info(
        self,
        method_idx: int,
    ) -> Tuple[
        str,
        str,
        str,
        List[str],
        str,
    ]:
        if not (
            0 <= method_idx < len(self.method_ids)
        ):
            return (
                "Lunknown/Class;",
                "unknownMethod",
                "()V",
                [],
                "void",
            )

        class_idx, proto_idx, name_idx = (
            self.method_ids[method_idx]
        )

        class_desc = self._get_type_str(class_idx)

        method_name = (
            self.strings[name_idx]
            if 0 <= name_idx < len(self.strings)
            else "unknown"
        )

        if 0 <= proto_idx < len(self.proto_ids):
            (
                shorty_idx,
                ret_idx,
                params_off,
            ) = self.proto_ids[proto_idx]

            ret_desc = self._get_type_str(ret_idx)

            params = self._get_proto_param_types(
                params_off
            )

            param_str = "".join(params)

            signature = (
                f"({param_str}){ret_desc}"
            )

            return (
                class_desc,
                method_name,
                signature,
                params,
                ret_desc,
            )

        return (
            class_desc,
            method_name,
            "()V",
            [],
            "V",
        )

    # -----------------------------------------------------------------------
    # Main DEX parse
    # -----------------------------------------------------------------------

    def parse(self) -> List[DexMethod]:
        if len(self.data) < 0x70:
            logger.warning(
                "DEX file %s too small (%d bytes)",
                self.dex_name,
                len(self.data),
            )
            return []

        magic = self.data[:8]

        if not magic.startswith(b"dex\n"):
            logger.warning(
                "Invalid DEX magic header in %s",
                self.dex_name,
            )
            return []

        try:
            header = struct.unpack_from(
                "<20I",
                self.data,
                0x20,
            )

            (
                file_size,
                header_size,
                endian_tag,
                link_size,
                link_off,
                map_off,
                string_ids_size,
                string_ids_off,
                type_ids_size,
                type_ids_off,
                proto_ids_size,
                proto_ids_off,
                field_ids_size,
                field_ids_off,
                method_ids_size,
                method_ids_off,
                class_defs_size,
                class_defs_off,
                data_size,
                data_off,
            ) = header

            # Basic header sanity.
            if header_size < 0x70:
                logger.warning(
                    "Invalid DEX header size in %s: %s",
                    self.dex_name,
                    header_size,
                )
                return []

            self.class_count = class_defs_size
            self.method_count = method_ids_size

            self._parse_string_ids(
                string_ids_size,
                string_ids_off,
            )

            self._parse_type_ids(
                type_ids_size,
                type_ids_off,
            )

            self._parse_proto_ids(
                proto_ids_size,
                proto_ids_off,
            )

            self._parse_field_ids(
                field_ids_size,
                field_ids_off,
            )

            self._parse_method_ids(
                method_ids_size,
                method_ids_off,
            )

            self._parse_class_defs(
                class_defs_size,
                class_defs_off,
            )

        except Exception as exc:
            logger.error(
                "Error parsing DEX %s: %s",
                self.dex_name,
                exc,
            )

        return self.methods

    # -----------------------------------------------------------------------
    # Class definitions
    # -----------------------------------------------------------------------

    def _parse_class_defs(
        self,
        count: int,
        offset: int,
    ):
        for i in range(count):
            class_def_offset = offset + i * 32

            packed = self._safe_unpack_from_data(
                "<IIIIIIII",
                class_def_offset,
            )

            if packed is None:
                logger.debug(
                    "Invalid class_def at index %d in %s",
                    i,
                    self.dex_name,
                )
                continue

            (
                class_idx,
                access_flags,
                superclass_idx,
                interfaces_off,
                source_file_idx,
                annotations_off,
                class_data_off,
                static_values_off,
            ) = packed

            class_desc = self._get_type_str(
                class_idx
            )

            clean_class = parse_type_descriptor(
                class_desc
            )

            package_name = (
                clean_class.rsplit(".", 1)[0]
                if "." in clean_class
                else ""
            )

            source_file = (
                self.strings[source_file_idx]
                if 0 <= source_file_idx < len(self.strings)
                else None
            )

            if (
                class_data_off == 0
                or class_data_off >= len(self.data)
            ):
                continue

            cur = class_data_off

            static_fields_size, cur = (
                read_uleb128(self.data, cur)
            )

            instance_fields_size, cur = (
                read_uleb128(self.data, cur)
            )

            direct_methods_size, cur = (
                read_uleb128(self.data, cur)
            )

            virtual_methods_size, cur = (
                read_uleb128(self.data, cur)
            )

            # Skip encoded fields.
            total_fields = (
                static_fields_size
                + instance_fields_size
            )

            for _ in range(total_fields):
                _, cur = read_uleb128(
                    self.data,
                    cur,
                )
                _, cur = read_uleb128(
                    self.data,
                    cur,
                )

            cur = self._parse_methods(
                cur,
                direct_methods_size,
                clean_class,
                package_name,
                source_file,
            )

            cur = self._parse_methods(
                cur,
                virtual_methods_size,
                clean_class,
                package_name,
                source_file,
            )

    # -----------------------------------------------------------------------
    # Purchase relevance fallback
    # -----------------------------------------------------------------------

    @classmethod
    def _is_purchase_related_name(
        cls,
        class_name: str,
        method_name: str,
    ) -> bool:
        combined = (
            f"{class_name}.{method_name}"
            .lower()
        )

        return any(
            keyword in combined
            for keyword in cls.PURCHASE_KEYWORDS
        )

    def _extract_url_strings_from_pool(
        self,
    ) -> List[str]:
        """
        Extract URL-like strings directly from the DEX String Pool.

        This is intentionally NOT attached to every method. It is only used
        as a conservative fallback for purchase-related methods that have no
        code_item/bytecode.
        """
        result: List[str] = []
        seen: Set[str] = set()

        for value in self.strings:
            if not value:
                continue

            for url in self.URL_REGEX.findall(value):
                url = url.rstrip(".,;)]}")

                if (
                    url
                    and url not in seen
                ):
                    seen.add(url)
                    result.append(url)

        return result

    def _fallback_strings_for_method(
        self,
        class_name: str,
        method_name: str,
    ) -> List[str]:
        """
        Conservative fallback for synthetic/minimal DEX files and methods
        without code.

        Real methods with bytecode are handled by _disassemble_bytecode(),
        so this fallback does not replace normal instruction-level analysis.
        """
        if not self._is_purchase_related_name(
            class_name,
            method_name,
        ):
            return []

        urls = self._extract_url_strings_from_pool()

        if urls:
            logger.debug(
                "Using DEX string-pool fallback for "
                "%s->%s: %d URL(s)",
                class_name,
                method_name,
                len(urls),
            )

        return urls

    # -----------------------------------------------------------------------
    # Method parsing
    # -----------------------------------------------------------------------

    def _parse_methods(
        self,
        offset: int,
        count: int,
        class_name: str,
        package_name: str,
        source_file: Optional[str],
    ) -> int:
        cur = offset
        method_idx = 0

        for _ in range(count):
            if cur >= len(self.data):
                break

            idx_diff, cur = read_uleb128(
                self.data,
                cur,
            )

            access_flags, cur = read_uleb128(
                self.data,
                cur,
            )

            code_off, cur = read_uleb128(
                self.data,
                cur,
            )

            method_idx += idx_diff

            (
                class_desc,
                method_name,
                signature,
                param_types,
                ret_desc,
            ) = self._get_method_info(
                method_idx
            )

            flags: List[str] = []

            if access_flags & self.ACC_PUBLIC:
                flags.append("public")

            if access_flags & self.ACC_PRIVATE:
                flags.append("private")

            if access_flags & self.ACC_PROTECTED:
                flags.append("protected")

            if access_flags & self.ACC_STATIC:
                flags.append("static")

            if access_flags & self.ACC_FINAL:
                flags.append("final")

            if access_flags & self.ACC_NATIVE:
                flags.append("native")

            if access_flags & self.ACC_ABSTRACT:
                flags.append("abstract")

            is_static = bool(
                access_flags & self.ACC_STATIC
            )

            is_native = bool(
                access_flags & self.ACC_NATIVE
            )

            is_abstract = bool(
                access_flags & self.ACC_ABSTRACT
            )

            is_constructor = (
                method_name in (
                    "<init>",
                    "<clinit>",
                )
            )

            callees: List[str] = []
            strings_ref: List[str] = []
            fields_ref: List[str] = []
            types_ref: List[str] = []
            instructions: List[InstructionDetail] = []
            branches: List[Dict[str, Any]] = []
            returns: List[Dict[str, Any]] = []
            unsupported: List[Dict[str, Any]] = []

            bytecode_snippet = None
            analysis_quality = "FULL"

            # ---------------------------------------------------------------
            # Normal code_item analysis
            # ---------------------------------------------------------------

            if (
                code_off > 0
                and self._has_range(
                    code_off,
                    16,
                )
            ):
                try:
                    (
                        registers_size,
                        ins_size,
                        outs_size,
                        tries_size,
                        debug_info_off,
                        insns_size,
                    ) = struct.unpack_from(
                        "<HHHHII",
                        self.data,
                        code_off,
                    )

                    insns_off = code_off + 16
                    requested_size = insns_size * 2

                    if (
                        requested_size > 0
                        and self._has_range(
                            insns_off,
                            requested_size,
                        )
                    ):
                        insns_bytes = self.data[
                            insns_off:
                            insns_off + requested_size
                        ]

                        (
                            callees,
                            strings_ref,
                            fields_ref,
                            types_ref,
                            instructions,
                            branches,
                            returns,
                            unsupported,
                            bytecode_snippet,
                            analysis_quality,
                        ) = self._disassemble_bytecode(
                            insns_bytes,
                            class_name,
                            method_name,
                        )

                    elif requested_size == 0:
                        analysis_quality = "PARTIAL"

                except Exception as exc:
                    logger.debug(
                        "Failed to parse code_item for "
                        "%s->%s: %s",
                        class_name,
                        method_name,
                        exc,
                    )
                    analysis_quality = "PARTIAL"

            # ---------------------------------------------------------------
            # Important fallback:
            #
            # Some synthetic/minimal DEX files contain method metadata but
            # code_off == 0 while useful URL strings remain in the String Pool.
            #
            # Do NOT attach the entire String Pool to every method.
            # Only purchase-related methods receive URL candidates.
            # ---------------------------------------------------------------

            if not strings_ref:
                fallback_strings = (
                    self._fallback_strings_for_method(
                        class_name,
                        method_name,
                    )
                )

                if fallback_strings:
                    strings_ref.extend(
                        fallback_strings
                    )

                    if analysis_quality == "FULL":
                        # The method has no bytecode, therefore the semantic
                        # association is weaker than instruction-level
                        # evidence.
                        analysis_quality = "PARTIAL"

            # Remove duplicates while preserving order.
            strings_ref = list(
                dict.fromkeys(strings_ref)
            )

            callees = list(
                dict.fromkeys(callees)
            )

            fields_ref = list(
                dict.fromkeys(fields_ref)
            )

            types_ref = list(
                dict.fromkeys(types_ref)
            )

            return_type_readable = (
                parse_type_descriptor(ret_desc)
            )

            method_obj = DexMethod(
                dex_file=self.dex_name,
                class_name=class_name,
                package=package_name,
                method_name=method_name,
                signature=signature,
                return_type=return_type_readable,
                source_apk=self.source_apk,
                parameters=[
                    parse_type_descriptor(p)
                    for p in param_types
                ],
                access_flags=flags,
                is_static=is_static,
                is_native=is_native,
                is_abstract=is_abstract,
                is_constructor=is_constructor,
                source_file=source_file,
                line_number=None,
                callers=[],
                callees=callees,
                strings_referenced=strings_ref,
                fields_referenced=fields_ref,
                types_referenced=types_ref,
                branches=branches,
                returns=returns,
                bytecode_snippet=bytecode_snippet,
                instructions=instructions,
                unsupported_opcodes=unsupported,
                analysis_quality=analysis_quality,
            )

            self.methods.append(method_obj)

        return cur

    # -----------------------------------------------------------------------
    # Bytecode disassembler
    # -----------------------------------------------------------------------

    def _disassemble_bytecode(
        self,
        insns: bytes,
        class_name: str,
        method_name: str,
    ) -> Tuple[
        List[str],
        List[str],
        List[str],
        List[str],
        List[InstructionDetail],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        Optional[str],
        str,
    ]:
        """Disassembles Dalvik bytecode into instruction details."""

        callees: List[str] = []
        strings_ref: List[str] = []
        fields_ref: List[str] = []
        types_ref: List[str] = []

        instruction_list: List[
            InstructionDetail
        ] = []

        branches: List[
            Dict[str, Any]
        ] = []

        returns: List[
            Dict[str, Any]
        ] = []

        unsupported: List[
            Dict[str, Any]
        ] = []

        lines: List[str] = []

        analysis_quality = "FULL"

        i = 0
        total_len = len(insns)

        while i < total_len:
            curr_offset = i // 2

            if i >= total_len:
                break

            opcode = insns[i]

            b1 = (
                insns[i + 1]
                if i + 1 < total_len
                else 0
            )

            # ---------------------------------------------------------------
            # Payload pseudo-instructions
            # ---------------------------------------------------------------

            if (
                opcode == 0x00
                and b1 in (0x01, 0x02, 0x03)
            ):
                payload_type = b1

                # packed-switch-payload
                if (
                    payload_type == 0x01
                    and i + 4 <= total_len
                ):
                    size = struct.unpack_from(
                        "<H",
                        insns,
                        i + 2,
                    )[0]

                    payload_len = (
                        (size * 2 + 4) * 2
                    )

                    raw = insns[
                        i:
                        min(
                            i + payload_len,
                            total_len,
                        )
                    ].hex()

                    instruction_list.append(
                        InstructionDetail(
                            offset=curr_offset,
                            opcode=0x0100,
                            opcode_name="packed-switch-payload",
                            raw_hex=raw,
                            operands=f"size={size}",
                            comment="switch jump table",
                        )
                    )

                    i += max(
                        2,
                        payload_len,
                    )

                    continue

                # sparse-switch-payload
                elif (
                    payload_type == 0x02
                    and i + 4 <= total_len
                ):
                    size = struct.unpack_from(
                        "<H",
                        insns,
                        i + 2,
                    )[0]

                    payload_len = (
                        (size * 4 + 2) * 2
                    )

                    raw = insns[
                        i:
                        min(
                            i + payload_len,
                            total_len,
                        )
                    ].hex()

                    instruction_list.append(
                        InstructionDetail(
                            offset=curr_offset,
                            opcode=0x0200,
                            opcode_name="sparse-switch-payload",
                            raw_hex=raw,
                            operands=f"size={size}",
                            comment="switch jump table",
                        )
                    )

                    i += max(
                        2,
                        payload_len,
                    )

                    continue

                # fill-array-data-payload
                elif (
                    payload_type == 0x03
                    and i + 8 <= total_len
                ):
                    elem_width = struct.unpack_from(
                        "<H",
                        insns,
                        i + 2,
                    )[0]

                    size = struct.unpack_from(
                        "<I",
                        insns,
                        i + 4,
                    )[0]

                    payload_bytes = (
                        elem_width * size
                    )

                    payload_len = (
                        (
                            payload_bytes + 1
                        ) // 2
                    ) * 2 + 8

                    raw = insns[
                        i:
                        min(
                            i + payload_len,
                            total_len,
                        )
                    ].hex()

                    instruction_list.append(
                        InstructionDetail(
                            offset=curr_offset,
                            opcode=0x0300,
                            opcode_name="fill-array-data-payload",
                            raw_hex=raw,
                            operands=(
                                f"width={elem_width}, "
                                f"size={size}"
                            ),
                            comment="array constants",
                        )
                    )

                    i += max(
                        2,
                        payload_len,
                    )

                    continue

            # ---------------------------------------------------------------
            # Opcode lookup
            # ---------------------------------------------------------------

            op_spec = OPCODE_INFO.get(opcode)

            if not op_spec:
                unsupported_entry = {
                    "opcode": f"0x{opcode:02x}",
                    "dex": self.dex_name,
                    "class": class_name,
                    "method": method_name,
                    "offset": f"0x{curr_offset:04x}",
                }

                unsupported.append(
                    unsupported_entry
                )

                self.unsupported_opcodes_log.append(
                    unsupported_entry
                )

                logger.warning(
                    "Unsupported opcode: 0x%02x, "
                    "DEX: %s, Method: %s->%s, "
                    "Offset: 0x%04x",
                    opcode,
                    self.dex_name,
                    class_name,
                    method_name,
                    curr_offset,
                )

                analysis_quality = "PARTIAL"

                # Unknown opcodes are advanced one code unit.
                i += 2
                continue

            (
                op_name,
                op_fmt,
                op_len,
            ) = op_spec

            if i + op_len > total_len:
                analysis_quality = "PARTIAL"
                break

            inst_bytes = insns[
                i:
                i + op_len
            ]

            raw_hex = inst_bytes.hex()

            operands = ""
            comment = ""

            registers: List[str] = []

            branch_target: Optional[int] = None
            ref_method: Optional[str] = None
            ref_field: Optional[str] = None
            ref_string: Optional[str] = None
            ref_type: Optional[str] = None

            # ---------------------------------------------------------------
            # 1. Invocation instructions
            # ---------------------------------------------------------------

            if opcode in (
                0x6E,
                0x6F,
                0x70,
                0x71,
                0x72,
            ):
                arg_count = (
                    (b1 >> 4) & 0x0F
                )

                method_idx = struct.unpack_from(
                    "<H",
                    inst_bytes,
                    2,
                )[0]

                (
                    c_desc,
                    m_name,
                    sig,
                    _,
                    _,
                ) = self._get_method_info(
                    method_idx
                )

                target_repr = (
                    f"{parse_type_descriptor(c_desc)}"
                    f"->{m_name}{sig}"
                )

                callees.append(
                    target_repr
                )

                ref_method = target_repr

                # 35c register layout:
                #
                # byte 4 = C | D
                # byte 5 = E | F
                # b1 low nibble = G
                #
                # The high nibble of b1 is A (argument count).
                r4 = (
                    inst_bytes[4]
                    if len(inst_bytes) > 4
                    else 0
                )

                r5 = (
                    inst_bytes[5]
                    if len(inst_bytes) > 5
                    else 0
                )

                reg_candidates = [
                    r4 & 0x0F,
                    (r4 >> 4) & 0x0F,
                    r5 & 0x0F,
                    (r5 >> 4) & 0x0F,
                    b1 & 0x0F,
                ]

                regs = [
                    f"v{r}"
                    for r in reg_candidates[
                        :arg_count
                    ]
                ]

                registers = regs

                operands = (
                    f"{{{', '.join(regs)}}}, "
                    f"{target_repr}"
                )

                comment = target_repr

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} {operands}"
                )

            # ---------------------------------------------------------------
            # 2. Invocation /range
            # ---------------------------------------------------------------

            elif opcode in (
                0x74,
                0x75,
                0x76,
                0x77,
                0x78,
            ):
                arg_count = b1

                method_idx = struct.unpack_from(
                    "<H",
                    inst_bytes,
                    2,
                )[0]

                start_reg = struct.unpack_from(
                    "<H",
                    inst_bytes,
                    4,
                )[0]

                (
                    c_desc,
                    m_name,
                    sig,
                    _,
                    _,
                ) = self._get_method_info(
                    method_idx
                )

                target_repr = (
                    f"{parse_type_descriptor(c_desc)}"
                    f"->{m_name}{sig}"
                )

                callees.append(
                    target_repr
                )

                ref_method = target_repr

                if arg_count == 0:
                    reg_str = "{}"
                elif arg_count == 1:
                    reg_str = (
                        f"{{v{start_reg}}}"
                    )
                else:
                    reg_str = (
                        f"{{v{start_reg} .. "
                        f"v{start_reg + arg_count - 1}}}"
                    )

                registers = [
                    f"v{start_reg + k}"
                    for k in range(arg_count)
                ]

                operands = (
                    f"{reg_str}, {target_repr}"
                )

                comment = target_repr

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} {operands}"
                )

            # ---------------------------------------------------------------
            # 3. Move results
            # ---------------------------------------------------------------

            elif opcode in (
                0x0A,
                0x0B,
                0x0C,
                0x0D,
            ):
                reg = b1

                registers = [
                    f"v{reg}"
                ]

                operands = (
                    f"v{reg}"
                )

                comment = (
                    f"Capture return value in v{reg}"
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} v{reg}"
                )

            # ---------------------------------------------------------------
            # 4. Returns
            # ---------------------------------------------------------------

            elif opcode in (
                0x0E,
                0x0F,
                0x10,
                0x11,
            ):
                if opcode == 0x0E:
                    operands = ""
                    registers = []
                else:
                    reg = b1

                    registers = [
                        f"v{reg}"
                    ]

                    operands = (
                        f"v{reg}"
                    )

                comment = "Method return point"

                returns.append(
                    {
                        "offset": curr_offset,
                        "opcode": op_name,
                        "register": (
                            operands
                            or None
                        ),
                    }
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} {operands}"
                    .strip()
                )

            # ---------------------------------------------------------------
            # 5. Conditional branches against zero
            # ---------------------------------------------------------------

            elif opcode in (
                0x38,
                0x39,
                0x3A,
                0x3B,
                0x3C,
                0x3D,
            ):
                reg = b1

                rel_offset = struct.unpack_from(
                    "<h",
                    inst_bytes,
                    2,
                )[0]

                target_off = (
                    curr_offset
                    + rel_offset
                )

                branch_target = target_off

                registers = [
                    f"v{reg}"
                ]

                operands = (
                    f"v{reg}, "
                    f"+0x{target_off:04x}"
                )

                if opcode == 0x38:
                    condition = "zero"
                    meaning = "== 0 (false)"
                elif opcode == 0x39:
                    condition = "nonzero"
                    meaning = "!= 0 (true)"
                else:
                    condition = "relative"
                    meaning = "comparison"

                comment = (
                    f"Branch to "
                    f"0x{target_off:04x} "
                    f"if v{reg} {meaning}"
                )

                branches.append(
                    {
                        "offset": curr_offset,
                        "opcode": op_name,
                        "target_offset": target_off,
                        "fallthrough_offset": (
                            curr_offset
                            + op_len // 2
                        ),
                        "register": f"v{reg}",
                        "condition": condition,
                    }
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"v{reg}, "
                    f"+0x{target_off:04x} "
                    f"# {comment}"
                )

            # ---------------------------------------------------------------
            # 6. Two-register conditionals
            # ---------------------------------------------------------------

            elif opcode in (
                0x32,
                0x33,
                0x34,
                0x35,
                0x36,
                0x37,
            ):
                rA = b1 & 0x0F
                rB = (
                    b1 >> 4
                ) & 0x0F

                rel_offset = struct.unpack_from(
                    "<h",
                    inst_bytes,
                    2,
                )[0]

                target_off = (
                    curr_offset
                    + rel_offset
                )

                branch_target = target_off

                registers = [
                    f"v{rA}",
                    f"v{rB}",
                ]

                operands = (
                    f"v{rA}, "
                    f"v{rB}, "
                    f"+0x{target_off:04x}"
                )

                comment = (
                    f"Branch to "
                    f"0x{target_off:04x}"
                )

                branches.append(
                    {
                        "offset": curr_offset,
                        "opcode": op_name,
                        "target_offset": target_off,
                        "fallthrough_offset": (
                            curr_offset
                            + op_len // 2
                        ),
                        "register": (
                            f"v{rA}, v{rB}"
                        ),
                        "condition": op_name,
                    }
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"v{rA}, v{rB}, "
                    f"+0x{target_off:04x}"
                )

            # ---------------------------------------------------------------
            # 7. Unconditional jumps
            # ---------------------------------------------------------------

            elif opcode in (
                0x28,
                0x29,
                0x2A,
            ):
                if opcode == 0x28:
                    rel_offset = struct.unpack_from(
                        "<b",
                        inst_bytes,
                        1,
                    )[0]
                elif opcode == 0x29:
                    rel_offset = struct.unpack_from(
                        "<h",
                        inst_bytes,
                        2,
                    )[0]
                else:
                    rel_offset = struct.unpack_from(
                        "<i",
                        inst_bytes,
                        2,
                    )[0]

                target_off = (
                    curr_offset
                    + rel_offset
                )

                branch_target = target_off

                operands = (
                    f"+0x{target_off:04x}"
                )

                comment = (
                    f"Jump to "
                    f"0x{target_off:04x}"
                )

                branches.append(
                    {
                        "offset": curr_offset,
                        "opcode": op_name,
                        "target_offset": target_off,
                        "fallthrough_offset": target_off,
                        "register": None,
                        "condition": "unconditional",
                    }
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"+0x{target_off:04x}"
                )

            # ---------------------------------------------------------------
            # 8. const-string / const-string/jumbo
            # ---------------------------------------------------------------

            elif opcode in (
                0x1A,
                0x1B,
            ):
                reg = b1

                registers = [
                    f"v{reg}"
                ]

                if opcode == 0x1A:
                    str_idx = struct.unpack_from(
                        "<H",
                        inst_bytes,
                        2,
                    )[0]
                else:
                    str_idx = struct.unpack_from(
                        "<I",
                        inst_bytes,
                        2,
                    )[0]

                s = (
                    self.strings[str_idx]
                    if 0 <= str_idx < len(self.strings)
                    else ""
                )

                if s:
                    strings_ref.append(s)

                ref_string = s

                sanitized_s = (
                    s.replace(
                        '"',
                        '\\"',
                    )
                    .replace(
                        "\n",
                        "\\n",
                    )
                )

                if len(sanitized_s) > 45:
                    sanitized_s = (
                        sanitized_s[:45]
                        + "..."
                    )

                operands = (
                    f'v{reg}, "{sanitized_s}"'
                )

                comment = s

                lines.append(
                    f'0x{curr_offset:04x}: '
                    f'{op_name} v{reg}, '
                    f'"{sanitized_s}"'
                )

            # ---------------------------------------------------------------
            # 9. Numeric constants
            # ---------------------------------------------------------------

            elif opcode in (
                0x12,
                0x13,
                0x14,
                0x15,
                0x16,
                0x17,
                0x18,
                0x19,
            ):
                if opcode == 0x12:
                    reg = b1 & 0x0F
                    val = (
                        b1 >> 4
                    ) & 0x0F

                    if val & 0x08:
                        val |= -16

                elif opcode in (
                    0x13,
                    0x16,
                ):
                    reg = b1
                    val = struct.unpack_from(
                        "<h",
                        inst_bytes,
                        2,
                    )[0]

                elif opcode in (
                    0x14,
                    0x17,
                ):
                    reg = b1
                    val = struct.unpack_from(
                        "<i",
                        inst_bytes,
                        2,
                    )[0]

                elif opcode in (
                    0x15,
                    0x19,
                ):
                    reg = b1

                    raw_val = struct.unpack_from(
                        "<h",
                        inst_bytes,
                        2,
                    )[0]

                    val = raw_val << 16

                else:
                    reg = b1

                    val = struct.unpack_from(
                        "<q",
                        inst_bytes,
                        2,
                    )[0]

                registers = [
                    f"v{reg}"
                ]

                operands = (
                    f"v{reg}, #{val}"
                )

                comment = (
                    f"v{reg} = {val}"
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"v{reg}, #{val}"
                )

            # ---------------------------------------------------------------
            # 10. Instance fields
            # ---------------------------------------------------------------

            elif 0x52 <= opcode <= 0x5F:
                rA = b1 & 0x0F
                rB = (
                    b1 >> 4
                ) & 0x0F

                field_idx = struct.unpack_from(
                    "<H",
                    inst_bytes,
                    2,
                )[0]

                (
                    c_name,
                    f_name,
                    f_type,
                ) = self._get_field_info(
                    field_idx
                )

                field_repr = (
                    f"{c_name}->{f_name}:"
                    f"{f_type}"
                )

                fields_ref.append(
                    field_repr
                )

                ref_field = field_repr

                registers = [
                    f"v{rA}",
                    f"v{rB}",
                ]

                operands = (
                    f"v{rA}, v{rB}, "
                    f"{field_repr}"
                )

                comment = field_repr

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"v{rA}, v{rB}, "
                    f"{field_repr}"
                )

            # ---------------------------------------------------------------
            # 11. Static fields
            # ---------------------------------------------------------------

            elif 0x60 <= opcode <= 0x6D:
                reg = b1

                field_idx = struct.unpack_from(
                    "<H",
                    inst_bytes,
                    2,
                )[0]

                (
                    c_name,
                    f_name,
                    f_type,
                ) = self._get_field_info(
                    field_idx
                )

                field_repr = (
                    f"{c_name}->{f_name}:"
                    f"{f_type}"
                )

                fields_ref.append(
                    field_repr
                )

                ref_field = field_repr

                registers = [
                    f"v{reg}"
                ]

                operands = (
                    f"v{reg}, "
                    f"{field_repr}"
                )

                comment = field_repr

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"v{reg}, "
                    f"{field_repr}"
                )

            # ---------------------------------------------------------------
            # 12. Type operations
            # ---------------------------------------------------------------

            elif opcode in (
                0x1C,
                0x1F,
                0x22,
            ):
                reg = b1

                type_idx = struct.unpack_from(
                    "<H",
                    inst_bytes,
                    2,
                )[0]

                t_str = parse_type_descriptor(
                    self._get_type_str(
                        type_idx
                    )
                )

                types_ref.append(
                    t_str
                )

                ref_type = t_str

                registers = [
                    f"v{reg}"
                ]

                operands = (
                    f"v{reg}, {t_str}"
                )

                comment = t_str

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"v{reg}, {t_str}"
                )

            # ---------------------------------------------------------------
            # 13. Move instructions
            # ---------------------------------------------------------------

            elif opcode in (
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
            ):
                if opcode in (
                    0x01,
                    0x04,
                    0x07,
                ):
                    rA = b1 & 0x0F
                    rB = (
                        b1 >> 4
                    ) & 0x0F

                elif opcode in (
                    0x02,
                    0x05,
                    0x08,
                ):
                    rA = b1

                    rB = struct.unpack_from(
                        "<H",
                        inst_bytes,
                        2,
                    )[0]

                else:
                    rA = struct.unpack_from(
                        "<H",
                        inst_bytes,
                        2,
                    )[0]

                    rB = struct.unpack_from(
                        "<H",
                        inst_bytes,
                        4,
                    )[0]

                registers = [
                    f"v{rA}",
                    f"v{rB}",
                ]

                operands = (
                    f"v{rA}, v{rB}"
                )

                comment = (
                    f"v{rA} = v{rB}"
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"v{rA}, v{rB}"
                )

            # ---------------------------------------------------------------
            # 14. Array operations
            # ---------------------------------------------------------------

            elif (
                0x44 <= opcode <= 0x51
                or opcode == 0x23
            ):
                if opcode == 0x23:
                    rA = b1 & 0x0F
                    rB = (
                        b1 >> 4
                    ) & 0x0F

                    type_idx = struct.unpack_from(
                        "<H",
                        inst_bytes,
                        2,
                    )[0]

                    t_str = parse_type_descriptor(
                        self._get_type_str(
                            type_idx
                        )
                    )

                    types_ref.append(
                        t_str
                    )

                    ref_type = t_str

                    registers = [
                        f"v{rA}",
                        f"v{rB}",
                    ]

                    operands = (
                        f"v{rA}, v{rB}, "
                        f"{t_str}"
                    )

                else:
                    rA = b1
                    rB = inst_bytes[2]
                    rC = inst_bytes[3]

                    registers = [
                        f"v{rA}",
                        f"v{rB}",
                        f"v{rC}",
                    ]

                    operands = (
                        f"v{rA}, "
                        f"v{rB}, "
                        f"v{rC}"
                    )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"{operands}"
                )

            # ---------------------------------------------------------------
            # 15. Generic fallback
            # ---------------------------------------------------------------

            else:
                operands = (
                    f"hex={raw_hex}"
                )

                lines.append(
                    f"0x{curr_offset:04x}: "
                    f"{op_name} "
                    f"{operands}"
                )

            detail = InstructionDetail(
                offset=curr_offset,
                opcode=opcode,
                opcode_name=op_name,
                raw_hex=raw_hex,
                operands=operands,
                registers=registers,
                branch_target=branch_target,
                referenced_method=ref_method,
                referenced_field=ref_field,
                referenced_string=ref_string,
                referenced_type=ref_type,
                comment=comment,
            )

            instruction_list.append(
                detail
            )

            i += op_len

        snippet = (
            "\n".join(lines)
            if lines
            else None
        )

        return (
            callees,
            strings_ref,
            fields_ref,
            types_ref,
            instruction_list,
            branches,
            returns,
            unsupported,
            snippet,
            analysis_quality,
        )


# ---------------------------------------------------------------------------
# Multi-DEX analyzer
# ---------------------------------------------------------------------------

class MultiDexAnalyzer:
    """Analyzes all DEX files across base and split APKs."""

    def __init__(
        self,
        apk_path: str,
        extracted_apks: Optional[
            List[Dict[str, Any]]
        ] = None,
    ):
        self.apk_path = apk_path
        self.extracted_apks = extracted_apks

        self.all_methods: List[
            DexMethod
        ] = []

        self.dex_files: List[
            DexFileInfo
        ] = []

        self.dex_strings: Dict[
            str,
            List[str],
        ] = {}

        self.unsupported_opcodes_total: List[
            Dict[str, Any]
        ] = []

    # -----------------------------------------------------------------------
    # APK / APKS extraction and DEX parsing
    # -----------------------------------------------------------------------

    def extract_and_parse(
        self,
    ) -> List[DexMethod]:
        from analyzer.core.apks_parser import (
            is_apks_container,
            ApksParser,
        )

        apks_to_process: List[
            Tuple[str, str, bool]
        ] = []

        # Explicitly supplied extracted APKs.
        if self.extracted_apks:
            for item in self.extracted_apks:
                extracted_path = item.get(
                    "extracted_path"
                )

                if not extracted_path:
                    continue

                apks_to_process.append(
                    (
                        extracted_path,
                        item.get(
                            "extracted_name",
                            os.path.basename(
                                extracted_path
                            ),
                        ),
                        item.get(
                            "is_base",
                            False,
                        ),
                    )
                )

        # .APKS container.
        elif is_apks_container(
            self.apk_path
        ):
            parser = ApksParser(
                self.apk_path
            )

            extracted = (
                parser.extract_and_discover()
            )

            for item in extracted:
                extracted_path = item.get(
                    "extracted_path"
                )

                if not extracted_path:
                    continue

                apks_to_process.append(
                    (
                        extracted_path,
                        item.get(
                            "extracted_name",
                            os.path.basename(
                                extracted_path
                            ),
                        ),
                        item.get(
                            "is_base",
                            False,
                        ),
                    )
                )

        # Normal APK.
        else:
            apks_to_process.append(
                (
                    self.apk_path,
                    "base.apk",
                    True,
                )
            )

        for (
            apk_file_path,
            apk_label,
            is_base,
        ) in apks_to_process:

            if not os.path.exists(
                apk_file_path
            ):
                logger.warning(
                    "APK path does not exist: %s",
                    apk_file_path,
                )
                continue

            try:
                with zipfile.ZipFile(
                    apk_file_path,
                    "r",
                ) as z:

                    dex_names = sorted(
                        [
                            n
                            for n in z.namelist()
                            if re.match(
                                r"^classes\d*\.dex$",
                                n,
                            )
                        ],
                        key=lambda x: (
                            len(x),
                            x,
                        ),
                    )

                    for dex_name in dex_names:
                        if is_base:
                            dex_key = dex_name
                        else:
                            dex_key = (
                                f"{apk_label}:"
                                f"{dex_name}"
                            )

                        try:
                            dex_data = z.read(
                                dex_name
                            )
                        except Exception as exc:
                            logger.error(
                                "Failed reading %s "
                                "from %s: %s",
                                dex_name,
                                apk_label,
                                exc,
                            )
                            continue

                        parser = DexParser(
                            dex_name,
                            dex_data,
                            source_apk=apk_label,
                        )

                        methods = parser.parse()

                        unsupported_count = len(
                            parser.unsupported_opcodes_log
                        )

                        self.unsupported_opcodes_total.extend(
                            parser.unsupported_opcodes_log
                        )

                        self.dex_files.append(
                            DexFileInfo(
                                name=dex_key,
                                source_apk=apk_label,
                                size_bytes=len(
                                    dex_data
                                ),
                                class_count=parser.class_count,
                                method_count=len(
                                    methods
                                ),
                                unsupported_opcodes_count=(
                                    unsupported_count
                                ),
                                analysis_quality=(
                                    "PARTIAL"
                                    if unsupported_count > 0
                                    else "FULL"
                                ),
                            )
                        )

                        self.dex_strings[
                            dex_key
                        ] = list(
                            parser.strings
                        )

                        self.all_methods.extend(
                            methods
                        )

            except zipfile.BadZipFile:
                logger.error(
                    "Invalid APK/ZIP file: %s",
                    apk_file_path,
                )

            except Exception as exc:
                logger.error(
                    "Error parsing APK %s (%s): %s",
                    apk_label,
                    apk_file_path,
                    exc,
                )

        self._build_caller_graph()

        return self.all_methods

    # -----------------------------------------------------------------------
    # Caller graph
    # -----------------------------------------------------------------------

    def _build_caller_graph(self):
        """
        Cross-reference callees to populate callers for all methods across
        all DEX files and split APKs.
        """
        method_map: Dict[
            str,
            DexMethod,
        ] = {}

        for method in self.all_methods:
            key_sig = (
                f"{method.class_name}"
                f"->{method.method_name}"
                f"{method.signature}"
            )

            key_base = (
                f"{method.class_name}"
                f"->{method.method_name}"
            )

            method_map[key_sig] = method

            if key_base not in method_map:
                method_map[key_base] = method

        for method in self.all_methods:
            caller_repr = (
                f"{method.class_name}"
                f"->{method.method_name}"
                f"{method.signature}"
            )

            for callee in method.callees:
                target_method = method_map.get(
                    callee
                )

                if target_method is None:
                    callee_base = (
                        callee.split("(")[0]
                    )

                    target_method = (
                        method_map.get(
                            callee_base
                        )
                    )

                if target_method is None:
                    continue

                if (
                    caller_repr
                    not in target_method.callers
                ):
                    target_method.callers.append(
                        caller_repr
                    )
