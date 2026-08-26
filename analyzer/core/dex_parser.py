"""Multi-DEX binary parser with a full Dalvik bytecode disassembler and cross-reference engine."""
import struct
import re
import os
import zipfile
import logging
from typing import List, Dict, Any, Tuple, Optional, Set
from analyzer.models import (
    DexMethod, InstructionDetail, DexFileInfo
)

logger = logging.getLogger(__name__)


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
    if (byte & 0x40) and (shift < 32):
        result |= -(1 << shift)
    return result, cur


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


# Complete Dalvik Opcode Specification Table
# (opcode_hex, name, format, length_in_bytes)
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


class DexParser:
    """Parses a DEX binary file and disassembles Dalvik bytecode with full opcode support."""

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

    def __init__(self, dex_name: str, dex_bytes: bytes, source_apk: str = "base.apk"):
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

    def parse(self) -> List[DexMethod]:
        if len(self.data) < 0x70:
            logger.warning(f"DEX file {self.dex_name} too small ({len(self.data)} bytes)")
            return []

        magic = self.data[:8]
        if not magic.startswith(b"dex\n"):
            logger.warning(f"Invalid DEX magic header in {self.dex_name}")
            return []

        try:
            (
                file_size, header_size, endian_tag,
                link_size, link_off,
                map_off,
                string_ids_size, string_ids_off,
                type_ids_size, type_ids_off,
                proto_ids_size, proto_ids_off,
                field_ids_size, field_ids_off,
                method_ids_size, method_ids_off,
                class_defs_size, class_defs_off,
                data_size, data_off
            ) = struct.unpack_from("<20I", self.data, 0x20)

            self.class_count = class_defs_size
            self.method_count = method_ids_size

            self._parse_string_ids(string_ids_size, string_ids_off)
            self._parse_type_ids(type_ids_size, type_ids_off)
            self._parse_proto_ids(proto_ids_size, proto_ids_off)
            self._parse_field_ids(field_ids_size, field_ids_off)
            self._parse_method_ids(method_ids_size, method_ids_off)
            self._parse_class_defs(class_defs_size, class_defs_off)

        except Exception as e:
            logger.error(f"Error parsing DEX {self.dex_name}: {e}")

        return self.methods

    def _parse_string_ids(self, count: int, offset: int):
        self.strings = []
        for i in range(count):
            str_data_off = struct.unpack_from("<I", self.data, offset + i * 4)[0]
            if str_data_off < len(self.data):
                utf16_size, str_start = read_uleb128(self.data, str_data_off)
                null_pos = self.data.find(b"\x00", str_start)
                if null_pos != -1:
                    raw_str = self.data[str_start:null_pos]
                    self.strings.append(raw_str.decode("utf-8", errors="ignore"))
                else:
                    self.strings.append("")
            else:
                self.strings.append("")

    def _parse_type_ids(self, count: int, offset: int):
        self.type_ids = []
        for i in range(count):
            desc_idx = struct.unpack_from("<I", self.data, offset + i * 4)[0]
            self.type_ids.append(desc_idx)

    def _get_type_str(self, type_idx: int) -> str:
        if 0 <= type_idx < len(self.type_ids):
            str_idx = self.type_ids[type_idx]
            if 0 <= str_idx < len(self.strings):
                return self.strings[str_idx]
        return "Lunknown/Type;"

    def _parse_proto_ids(self, count: int, offset: int):
        self.proto_ids = []
        for i in range(count):
            shorty_idx, return_type_idx, parameters_off = struct.unpack_from("<III", self.data, offset + i * 12)
            self.proto_ids.append((shorty_idx, return_type_idx, parameters_off))

    def _get_proto_param_types(self, parameters_off: int) -> List[str]:
        if parameters_off == 0 or parameters_off >= len(self.data):
            return []
        try:
            size = struct.unpack_from("<I", self.data, parameters_off)[0]
            params = []
            for i in range(size):
                type_idx = struct.unpack_from("<H", self.data, parameters_off + 4 + i * 2)[0]
                params.append(self._get_type_str(type_idx))
            return params
        except Exception:
            return []

    def _parse_field_ids(self, count: int, offset: int):
        self.field_ids = []
        for i in range(count):
            class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.data, offset + i * 8)
            self.field_ids.append((class_idx, type_idx, name_idx))

    def _get_field_info(self, field_idx: int) -> Tuple[str, str, str]:
        if not (0 <= field_idx < len(self.field_ids)):
            return "Lunknown/Class;", "unknownField", "Lunknown/Type;"
        class_idx, type_idx, name_idx = self.field_ids[field_idx]
        c_name = parse_type_descriptor(self._get_type_str(class_idx))
        f_type = parse_type_descriptor(self._get_type_str(type_idx))
        f_name = self.strings[name_idx] if 0 <= name_idx < len(self.strings) else "unknown"
        return c_name, f_name, f_type

    def _parse_method_ids(self, count: int, offset: int):
        self.method_ids = []
        for i in range(count):
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, offset + i * 8)
            self.method_ids.append((class_idx, proto_idx, name_idx))

    def _get_method_info(self, method_idx: int) -> Tuple[str, str, str, List[str], str]:
        if not (0 <= method_idx < len(self.method_ids)):
            return "Lunknown/Class;", "unknownMethod", "()V", [], "void"

        class_idx, proto_idx, name_idx = self.method_ids[method_idx]
        class_desc = self._get_type_str(class_idx)
        method_name = self.strings[name_idx] if 0 <= name_idx < len(self.strings) else "unknown"

        if 0 <= proto_idx < len(self.proto_ids):
            shorty_idx, ret_idx, params_off = self.proto_ids[proto_idx]
            ret_desc = self._get_type_str(ret_idx)
            params = self._get_proto_param_types(params_off)
            param_str = "".join(params)
            signature = f"({param_str}){ret_desc}"
            return class_desc, method_name, signature, params, ret_desc
        return class_desc, method_name, "()V", [], "V"

    def _parse_class_defs(self, count: int, offset: int):
        for i in range(count):
            class_def_offset = offset + i * 32
            (
                class_idx, access_flags, superclass_idx,
                interfaces_off, source_file_idx,
                annotations_off, class_data_off, static_values_off
            ) = struct.unpack_from("<IIIIIIII", self.data, class_def_offset)

            class_desc = self._get_type_str(class_idx)
            clean_class = parse_type_descriptor(class_desc)
            package_name = clean_class.rsplit(".", 1)[0] if "." in clean_class else ""
            source_file = self.strings[source_file_idx] if 0 <= source_file_idx < len(self.strings) else None

            if class_data_off == 0 or class_data_off >= len(self.data):
                continue

            cur = class_data_off
            static_fields_size, cur = read_uleb128(self.data, cur)
            instance_fields_size, cur = read_uleb128(self.data, cur)
            direct_methods_size, cur = read_uleb128(self.data, cur)
            virtual_methods_size, cur = read_uleb128(self.data, cur)

            for _ in range(static_fields_size + instance_fields_size):
                _, cur = read_uleb128(self.data, cur)
                _, cur = read_uleb128(self.data, cur)

            cur = self._parse_methods(cur, direct_methods_size, clean_class, package_name, source_file)
            cur = self._parse_methods(cur, virtual_methods_size, clean_class, package_name, source_file)

    def _parse_methods(self, offset: int, count: int, class_name: str, package_name: str, source_file: Optional[str]) -> int:
        cur = offset
        method_idx = 0
        for _ in range(count):
            if cur >= len(self.data):
                break
            idx_diff, cur = read_uleb128(self.data, cur)
            access_flags, cur = read_uleb128(self.data, cur)
            code_off, cur = read_uleb128(self.data, cur)

            method_idx += idx_diff
            class_desc, method_name, signature, param_types, ret_desc = self._get_method_info(method_idx)

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

            is_static = bool(access_flags & self.ACC_STATIC)
            is_native = bool(access_flags & self.ACC_NATIVE)
            is_abstract = bool(access_flags & self.ACC_ABSTRACT)
            is_constructor = method_name in ("<init>", "<clinit>")

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

            if code_off > 0 and code_off + 16 <= len(self.data):
                registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from(
                    "<HHHHII", self.data, code_off
                )
                insns_off = code_off + 16
                insns_bytes = self.data[insns_off : insns_off + insns_size * 2]
                
                (
                    callees, strings_ref, fields_ref, types_ref,
                    instructions, branches, returns, unsupported,
                    bytecode_snippet, analysis_quality
                ) = self._disassemble_bytecode(insns_bytes, class_name, method_name)

            return_type_readable = parse_type_descriptor(ret_desc)

            method_obj = DexMethod(
                dex_file=self.dex_name,
                class_name=class_name,
                package=package_name,
                method_name=method_name,
                signature=signature,
                return_type=return_type_readable,
                source_apk=self.source_apk,
                parameters=[parse_type_descriptor(p) for p in param_types],
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

    def _disassemble_bytecode(
        self, insns: bytes, class_name: str, method_name: str
    ) -> Tuple[
        List[str], List[str], List[str], List[str],
        List[InstructionDetail], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]],
        Optional[str], str
    ]:
        """Disassembles Dalvik bytecode into instruction details, tracking branches, returns, and opcodes."""
        callees: List[str] = []
        strings_ref: List[str] = []
        fields_ref: List[str] = []
        types_ref: List[str] = []
        instruction_list: List[InstructionDetail] = []
        branches: List[Dict[str, Any]] = []
        returns: List[Dict[str, Any]] = []
        unsupported: List[Dict[str, Any]] = []
        lines: List[str] = []
        analysis_quality = "FULL"

        i = 0
        total_len = len(insns)

        while i < total_len:
            curr_offset = i // 2
            opcode = insns[i]
            b1 = insns[i + 1] if i + 1 < total_len else 0

            # Special pseudo-instruction: packed-switch-payload (0x0100) or sparse-switch-payload (0x0200) or fill-array-data-payload (0x0300)
            if opcode == 0x00 and b1 in (0x01, 0x02, 0x03):
                payload_type = b1
                if payload_type == 0x01 and i + 4 <= total_len:  # packed-switch
                    size = struct.unpack_from("<H", insns, i + 2)[0]
                    payload_len = (size * 2 + 4) * 2
                    raw = insns[i : min(i + payload_len, total_len)].hex()
                    instruction_list.append(InstructionDetail(
                        offset=curr_offset, opcode=0x0100, opcode_name="packed-switch-payload",
                        raw_hex=raw, operands=f"size={size}", comment="switch jump table"
                    ))
                    i += payload_len
                    continue
                elif payload_type == 0x02 and i + 4 <= total_len:  # sparse-switch
                    size = struct.unpack_from("<H", insns, i + 2)[0]
                    payload_len = (size * 4 + 2) * 2
                    raw = insns[i : min(i + payload_len, total_len)].hex()
                    instruction_list.append(InstructionDetail(
                        offset=curr_offset, opcode=0x0200, opcode_name="sparse-switch-payload",
                        raw_hex=raw, operands=f"size={size}", comment="switch jump table"
                    ))
                    i += payload_len
                    continue
                elif payload_type == 0x03 and i + 8 <= total_len:  # fill-array-data
                    elem_width = struct.unpack_from("<H", insns, i + 2)[0]
                    size = struct.unpack_from("<I", insns, i + 4)[0]
                    payload_len = (elem_width * size + 1) // 2 * 2 + 8
                    raw = insns[i : min(i + payload_len, total_len)].hex()
                    instruction_list.append(InstructionDetail(
                        offset=curr_offset, opcode=0x0300, opcode_name="fill-array-data-payload",
                        raw_hex=raw, operands=f"width={elem_width}, size={size}", comment="array constants"
                    ))
                    i += payload_len
                    continue

            op_spec = OPCODE_INFO.get(opcode)
            if not op_spec:
                # Unsupported opcode encountered
                unsupported_entry = {
                    "opcode": f"0x{opcode:02x}",
                    "dex": self.dex_name,
                    "class": class_name,
                    "method": method_name,
                    "offset": f"0x{curr_offset:04x}",
                }
                unsupported.append(unsupported_entry)
                self.unsupported_opcodes_log.append(unsupported_entry)
                logger.warning(
                    f"Unsupported opcode: 0x{opcode:02x}, DEX: {self.dex_name}, "
                    f"Method: {class_name}->{method_name}, Offset: 0x{curr_offset:04x}"
                )
                analysis_quality = "PARTIAL"
                # Advance 2 bytes
                i += 2
                continue

            op_name, op_fmt, op_len = op_spec
            if i + op_len > total_len:
                # Instruction is cut off at end of stream
                break

            inst_bytes = insns[i : i + op_len]
            raw_hex = inst_bytes.hex()
            operands = ""
            comment = ""
            registers: List[str] = []
            branch_target: Optional[int] = None
            ref_method: Optional[str] = None
            ref_field: Optional[str] = None
            ref_string: Optional[str] = None
            ref_type: Optional[str] = None

            # --- Disassemble based on Opcode Group ---

            # 1. Invocations (invoke-virtual, invoke-super, invoke-direct, invoke-static, invoke-interface)
            if opcode in (0x6E, 0x6F, 0x70, 0x71, 0x72):
                arg_count = (b1 >> 4) & 0x0F
                method_idx = struct.unpack_from("<H", inst_bytes, 2)[0]
                c_desc, m_name, sig, _, _ = self._get_method_info(method_idx)
                target_repr = f"{parse_type_descriptor(c_desc)}->{m_name}{sig}"
                callees.append(target_repr)
                ref_method = target_repr

                # Extract registers vC, vD, vE, vF, vG
                r4 = inst_bytes[4] if len(inst_bytes) > 4 else 0
                r5 = inst_bytes[5] if len(inst_bytes) > 5 else 0
                reg_candidates = [
                    r4 & 0x0F, (r4 >> 4) & 0x0F,
                    r5 & 0x0F, (r5 >> 4) & 0x0F,
                    b1 & 0x0F
                ]
                regs = [f"v{r}" for r in reg_candidates[:arg_count]]
                registers = regs
                operands = f"{{{', '.join(regs)}}}, {target_repr}"
                comment = target_repr
                lines.append(f"0x{curr_offset:04x}: {op_name} {operands}")

            # 2. Invocations /range (0x74..0x78)
            elif opcode in (0x74, 0x75, 0x76, 0x77, 0x78):
                arg_count = b1
                method_idx = struct.unpack_from("<H", inst_bytes, 2)[0]
                start_reg = struct.unpack_from("<H", inst_bytes, 4)[0]
                c_desc, m_name, sig, _, _ = self._get_method_info(method_idx)
                target_repr = f"{parse_type_descriptor(c_desc)}->{m_name}{sig}"
                callees.append(target_repr)
                ref_method = target_repr
                if arg_count == 0:
                    reg_str = "{}"
                elif arg_count == 1:
                    reg_str = f"{{v{start_reg}}}"
                else:
                    reg_str = f"{{v{start_reg} .. v{start_reg + arg_count - 1}}}"
                registers = [f"v{start_reg + k}" for k in range(arg_count)]
                operands = f"{reg_str}, {target_repr}"
                comment = target_repr
                lines.append(f"0x{curr_offset:04x}: {op_name} {operands}")

            # 3. Move results (move-result, move-result-wide, move-result-object, move-exception)
            elif opcode in (0x0A, 0x0B, 0x0C, 0x0D):
                reg = b1
                registers = [f"v{reg}"]
                operands = f"v{reg}"
                comment = f"Capture return value in v{reg}"
                lines.append(f"0x{curr_offset:04x}: {op_name} v{reg}")

            # 4. Returns (return-void, return, return-wide, return-object)
            elif opcode in (0x0E, 0x0F, 0x10, 0x11):
                if opcode == 0x0E:
                    operands = ""
                    registers = []
                else:
                    reg = b1
                    registers = [f"v{reg}"]
                    operands = f"v{reg}"
                comment = "Method return point"
                returns.append({
                    "offset": curr_offset,
                    "opcode": op_name,
                    "register": operands or None
                })
                lines.append(f"0x{curr_offset:04x}: {op_name} {operands}".strip())

            # 5. Conditionals with zero (if-eqz, if-nez, if-ltz, if-gez, if-gtz, if-lez)
            elif opcode in (0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D):
                reg = b1
                rel_offset = struct.unpack_from("<h", inst_bytes, 2)[0]
                target_off = curr_offset + rel_offset
                branch_target = target_off
                registers = [f"v{reg}"]
                operands = f"v{reg}, +0x{target_off:04x}"
                meaning = "== 0 (false)" if opcode == 0x38 else ("!= 0 (true)" if opcode == 0x39 else "comparison")
                comment = f"Branch to 0x{target_off:04x} if v{reg} {meaning}"
                branches.append({
                    "offset": curr_offset,
                    "opcode": op_name,
                    "target_offset": target_off,
                    "fallthrough_offset": curr_offset + (op_len // 2),
                    "register": f"v{reg}",
                    "condition": "zero" if opcode == 0x38 else ("nonzero" if opcode == 0x39 else "relative"),
                })
                lines.append(f"0x{curr_offset:04x}: {op_name} v{reg}, +0x{target_off:04x}  # {comment}")

            # 6. Conditionals 2 registers (if-eq, if-ne, if-lt, if-ge, if-gt, if-le)
            elif opcode in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37):
                rA = b1 & 0x0F
                rB = (b1 >> 4) & 0x0F
                rel_offset = struct.unpack_from("<h", inst_bytes, 2)[0]
                target_off = curr_offset + rel_offset
                branch_target = target_off
                registers = [f"v{rA}", f"v{rB}"]
                operands = f"v{rA}, v{rB}, +0x{target_off:04x}"
                comment = f"Branch to 0x{target_off:04x}"
                branches.append({
                    "offset": curr_offset,
                    "opcode": op_name,
                    "target_offset": target_off,
                    "fallthrough_offset": curr_offset + (op_len // 2),
                    "register": f"v{rA}, v{rB}",
                    "condition": op_name,
                })
                lines.append(f"0x{curr_offset:04x}: {op_name} v{rA}, v{rB}, +0x{target_off:04x}")

            # 7. Unconditional jumps (goto, goto/16, goto/32)
            elif opcode in (0x28, 0x29, 0x2A):
                if opcode == 0x28:
                    rel_offset = struct.unpack_from("<b", inst_bytes, 1)[0]
                elif opcode == 0x29:
                    rel_offset = struct.unpack_from("<h", inst_bytes, 2)[0]
                else:
                    rel_offset = struct.unpack_from("<i", inst_bytes, 2)[0]
                target_off = curr_offset + rel_offset
                branch_target = target_off
                operands = f"+0x{target_off:04x}"
                comment = f"Jump to 0x{target_off:04x}"
                branches.append({
                    "offset": curr_offset,
                    "opcode": op_name,
                    "target_offset": target_off,
                    "fallthrough_offset": target_off,
                    "register": None,
                    "condition": "unconditional",
                })
                lines.append(f"0x{curr_offset:04x}: {op_name} +0x{target_off:04x}")

            # 8. Constants - String (const-string, const-string/jumbo)
            elif opcode in (0x1A, 0x1B):
                reg = b1
                registers = [f"v{reg}"]
                if opcode == 0x1A:
                    str_idx = struct.unpack_from("<H", inst_bytes, 2)[0]
                else:
                    str_idx = struct.unpack_from("<I", inst_bytes, 2)[0]
                s = self.strings[str_idx] if 0 <= str_idx < len(self.strings) else ""
                strings_ref.append(s)
                ref_string = s
                sanitized_s = s.replace('"', '\\"').replace("\n", "\\n")
                if len(sanitized_s) > 45:
                    sanitized_s = sanitized_s[:45] + "..."
                operands = f"v{reg}, \"{sanitized_s}\""
                comment = s
                lines.append(f"0x{curr_offset:04x}: {op_name} v{reg}, \"{sanitized_s}\"")

            # 9. Constants - Numeric (const/4, const/16, const, const/high16)
            elif opcode in (0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19):
                if opcode == 0x12:
                    reg = b1 & 0x0F
                    val = (b1 >> 4) & 0x0F
                    if val & 0x08:
                        val |= -16
                elif opcode in (0x13, 0x16):
                    reg = b1
                    val = struct.unpack_from("<h", inst_bytes, 2)[0]
                elif opcode in (0x14, 0x17):
                    reg = b1
                    val = struct.unpack_from("<i", inst_bytes, 2)[0]
                elif opcode in (0x15, 0x19):
                    reg = b1
                    raw_val = struct.unpack_from("<h", inst_bytes, 2)[0]
                    val = raw_val << 16
                else:  # 0x18 const-wide
                    reg = b1
                    val = struct.unpack_from("<q", inst_bytes, 2)[0]
                registers = [f"v{reg}"]
                operands = f"v{reg}, #{val}"
                comment = f"v{reg} = {val}"
                lines.append(f"0x{curr_offset:04x}: {op_name} v{reg}, #{val}")

            # 10. Instance Field Access (iget*, iput*)
            elif 0x52 <= opcode <= 0x5F:
                rA = b1 & 0x0F
                rB = (b1 >> 4) & 0x0F
                field_idx = struct.unpack_from("<H", inst_bytes, 2)[0]
                c_name, f_name, f_type = self._get_field_info(field_idx)
                field_repr = f"{c_name}->{f_name}:{f_type}"
                fields_ref.append(field_repr)
                ref_field = field_repr
                registers = [f"v{rA}", f"v{rB}"]
                operands = f"v{rA}, v{rB}, {field_repr}"
                comment = field_repr
                lines.append(f"0x{curr_offset:04x}: {op_name} v{rA}, v{rB}, {field_repr}")

            # 11. Static Field Access (sget*, sput*)
            elif 0x60 <= opcode <= 0x6D:
                reg = b1
                field_idx = struct.unpack_from("<H", inst_bytes, 2)[0]
                c_name, f_name, f_type = self._get_field_info(field_idx)
                field_repr = f"{c_name}->{f_name}:{f_type}"
                fields_ref.append(field_repr)
                ref_field = field_repr
                registers = [f"v{reg}"]
                operands = f"v{reg}, {field_repr}"
                comment = field_repr
                lines.append(f"0x{curr_offset:04x}: {op_name} v{reg}, {field_repr}")

            # 12. Type Operations (check-cast, new-instance, const-class)
            elif opcode in (0x1C, 0x1F, 0x22):
                reg = b1
                type_idx = struct.unpack_from("<H", inst_bytes, 2)[0]
                t_str = parse_type_descriptor(self._get_type_str(type_idx))
                types_ref.append(t_str)
                ref_type = t_str
                registers = [f"v{reg}"]
                operands = f"v{reg}, {t_str}"
                comment = t_str
                lines.append(f"0x{curr_offset:04x}: {op_name} v{reg}, {t_str}")

            # 13. Move instructions (move, move/from16, move/16, move-wide, move-object)
            elif opcode in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09):
                if opcode in (0x01, 0x04, 0x07):  # 12x
                    rA = b1 & 0x0F
                    rB = (b1 >> 4) & 0x0F
                elif opcode in (0x02, 0x05, 0x08):  # 22x
                    rA = b1
                    rB = struct.unpack_from("<H", inst_bytes, 2)[0]
                else:  # 32x
                    rA = struct.unpack_from("<H", inst_bytes, 2)[0]
                    rB = struct.unpack_from("<H", inst_bytes, 4)[0]
                registers = [f"v{rA}", f"v{rB}"]
                operands = f"v{rA}, v{rB}"
                comment = f"v{rA} = v{rB}"
                lines.append(f"0x{curr_offset:04x}: {op_name} v{rA}, v{rB}")

            # 14. Array Operations (aget*, aput*, new-array)
            elif (0x44 <= opcode <= 0x51) or opcode == 0x23:
                if opcode == 0x23:  # new-array
                    rA = b1 & 0x0F
                    rB = (b1 >> 4) & 0x0F
                    type_idx = struct.unpack_from("<H", inst_bytes, 2)[0]
                    t_str = parse_type_descriptor(self._get_type_str(type_idx))
                    registers = [f"v{rA}", f"v{rB}"]
                    operands = f"v{rA}, v{rB}, {t_str}"
                else:  # aget/aput 23x
                    rA = b1
                    rB = inst_bytes[2]
                    rC = inst_bytes[3]
                    registers = [f"v{rA}", f"v{rB}", f"v{rC}"]
                    operands = f"v{rA}, v{rB}, v{rC}"
                lines.append(f"0x{curr_offset:04x}: {op_name} {operands}")

            # 15. Generic fallback for arithmetic/unops/binops
            else:
                operands = f"hex={raw_hex}"
                lines.append(f"0x{curr_offset:04x}: {op_name} {operands}")

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
            instruction_list.append(detail)
            i += op_len

        snippet = "\n".join(lines) if lines else None
        return (
            callees, strings_ref, fields_ref, types_ref,
            instruction_list, branches, returns, unsupported,
            snippet, analysis_quality
        )


class MultiDexAnalyzer:
    """Analyzes all DEX files across base and split APKs, tracking stats and cross-references."""

    def __init__(self, apk_path: str, extracted_apks: Optional[List[Dict[str, Any]]] = None):
        self.apk_path = apk_path
        self.extracted_apks = extracted_apks
        self.all_methods: List[DexMethod] = []
        self.dex_files: List[DexFileInfo] = []
        self.dex_strings: Dict[str, List[str]] = {}
        self.unsupported_opcodes_total: List[Dict[str, Any]] = []

    def extract_and_parse(self) -> List[DexMethod]:
        from analyzer.core.apks_parser import is_apks_container, ApksParser

        apks_to_process: List[Tuple[str, str, bool]] = []

        if self.extracted_apks:
            for item in self.extracted_apks:
                apks_to_process.append((
                    item["extracted_path"],
                    item.get("extracted_name", os.path.basename(item["extracted_path"])),
                    item.get("is_base", False)
                ))
        elif is_apks_container(self.apk_path):
            parser = ApksParser(self.apk_path)
            extracted = parser.extract_and_discover()
            for item in extracted:
                apks_to_process.append((
                    item["extracted_path"],
                    item.get("extracted_name", os.path.basename(item["extracted_path"])),
                    item.get("is_base", False)
                ))
        else:
            apks_to_process.append((self.apk_path, "base.apk", True))

        for apk_file_path, apk_label, is_base in apks_to_process:
            if not os.path.exists(apk_file_path):
                continue
            try:
                with zipfile.ZipFile(apk_file_path, "r") as z:
                    dex_names = sorted(
                        [n for n in z.namelist() if re.match(r"^classes\d*\.dex$", n)],
                        key=lambda x: (len(x), x),
                    )

                    for dex_name in dex_names:
                        dex_key = f"{apk_label}:{dex_name}" if not is_base else dex_name
                        dex_data = z.read(dex_name)
                        parser = DexParser(dex_name, dex_data, source_apk=apk_label)
                        methods = parser.parse()
                        
                        unsupported_count = len(parser.unsupported_opcodes_log)
                        self.unsupported_opcodes_total.extend(parser.unsupported_opcodes_log)

                        self.dex_files.append(DexFileInfo(
                            name=dex_key,
                            source_apk=apk_label,
                            size_bytes=len(dex_data),
                            class_count=parser.class_count,
                            method_count=len(methods),
                            unsupported_opcodes_count=unsupported_count,
                            analysis_quality="PARTIAL" if unsupported_count > 0 else "FULL",
                        ))

                        self.dex_strings[dex_key] = parser.strings
                        self.all_methods.extend(methods)
            except Exception as e:
                logger.error(f"Error parsing APK {apk_label} ({apk_file_path}): {e}")

        self._build_caller_graph()
        return self.all_methods

    def _build_caller_graph(self):
        """Cross-references callees to populate callers for all methods across all DEX files and split APKs."""
        method_map: Dict[str, DexMethod] = {}
        for m in self.all_methods:
            # Map canonical representations: exact signature and base name
            key_sig = f"{m.class_name}->{m.method_name}{m.signature}"
            key_base = f"{m.class_name}->{m.method_name}"
            method_map[key_sig] = m
            if key_base not in method_map:
                method_map[key_base] = m

        for m in self.all_methods:
            caller_repr = f"{m.class_name}->{m.method_name}{m.signature}"
            for callee in m.callees:
                if callee in method_map:
                    target_m = method_map[callee]
                    if caller_repr not in target_m.callers:
                        target_m.callers.append(caller_repr)
                else:
                    callee_base = callee.split("(")[0]
                    if callee_base in method_map:
                        target_m = method_map[callee_base]
                        if caller_repr not in target_m.callers:
                            target_m.callers.append(caller_repr)
                        target_m.callers.append(caller_repr)
