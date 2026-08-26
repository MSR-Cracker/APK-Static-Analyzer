"""Multi-DEX binary parser extracting classes, methods, signatures, Dalvik bytecode, and cross-references."""
import struct
import re
import os
import zipfile
import logging
from typing import List, Dict, Any, Tuple, Optional, Set
from analyzer.models import DexMethod

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


def parse_method_signature(shorty: str, proto_params: List[str], return_type_desc: str) -> Tuple[List[str], str]:
    params = [parse_type_descriptor(p) for p in proto_params]
    ret = parse_type_descriptor(return_type_desc)
    return params, ret


class DexParser:
    """Parses a single DEX binary file."""

    # Access flags
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

    def __init__(self, dex_name: str, dex_bytes: bytes):
        self.dex_name = dex_name
        self.data = dex_bytes
        self.strings: List[str] = []
        self.type_ids: List[int] = []  # index into strings
        self.proto_ids: List[Tuple[int, int, int]] = []  # (shorty_idx, return_type_idx, parameters_off)
        self.field_ids: List[Tuple[int, int, int]] = []  # (class_idx, type_idx, name_idx)
        self.method_ids: List[Tuple[int, int, int]] = []  # (class_idx, proto_idx, name_idx)
        self.methods: List[DexMethod] = []
        self.string_references: Dict[int, Set[str]] = {}  # method_idx -> set of strings

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

            # 1. Parse String IDs
            self._parse_string_ids(string_ids_size, string_ids_off)

            # 2. Parse Type IDs
            self._parse_type_ids(type_ids_size, type_ids_off)

            # 3. Parse Proto IDs
            self._parse_proto_ids(proto_ids_size, proto_ids_off)

            # 4. Parse Field IDs
            self._parse_field_ids(field_ids_size, field_ids_off)

            # 5. Parse Method IDs
            self._parse_method_ids(method_ids_size, method_ids_off)

            # 6. Parse Class Definitions & Methods
            self._parse_class_defs(class_defs_size, class_defs_off)

        except Exception as e:
            logger.error(f"Error parsing DEX {self.dex_name}: {e}")

        return self.methods

    def _parse_string_ids(self, count: int, offset: int):
        self.strings = []
        for i in range(count):
            str_data_off = struct.unpack_from("<I", self.data, offset + i * 4)[0]
            if str_data_off < len(self.data):
                # read uleb128 utf16_size
                utf16_size, str_start = read_uleb128(self.data, str_data_off)
                # find null terminator
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

            # Parse class_data_item
            cur = class_data_off
            static_fields_size, cur = read_uleb128(self.data, cur)
            instance_fields_size, cur = read_uleb128(self.data, cur)
            direct_methods_size, cur = read_uleb128(self.data, cur)
            virtual_methods_size, cur = read_uleb128(self.data, cur)

            # Skip fields
            for _ in range(static_fields_size + instance_fields_size):
                _, cur = read_uleb128(self.data, cur)
                _, cur = read_uleb128(self.data, cur)

            # Parse direct methods
            self._parse_method_list(cur, direct_methods_size, clean_class, package_name, source_file)
            # Parse virtual methods
            # Need to advance cur over direct methods first
            cur_virtual = cur
            last_idx = 0
            for _ in range(direct_methods_size):
                diff, cur_virtual = read_uleb128(self.data, cur_virtual)
                _, cur_virtual = read_uleb128(self.data, cur_virtual)
                code_off, cur_virtual = read_uleb128(self.data, cur_virtual)

            self._parse_method_list(cur_virtual, virtual_methods_size, clean_class, package_name, source_file)

    def _parse_method_list(self, offset: int, count: int, class_name: str, package_name: str, source_file: Optional[str]):
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

            # Access modifiers
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
            is_constructor = method_name == "<init>" or method_name == "<clinit>"

            callees: List[str] = []
            strings_ref: List[str] = []
            bytecode_snippet = None

            # Disassemble bytecode instructions if code_off != 0
            if code_off > 0 and code_off + 16 <= len(self.data):
                registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from(
                    "<HHHHII", self.data, code_off
                )
                insns_off = code_off + 16
                insns_bytes = self.data[insns_off : insns_off + insns_size * 2]
                callees, strings_ref, bytecode_snippet = self._disassemble_snippet(insns_bytes)

            return_type_readable = parse_type_descriptor(ret_desc)

            method_obj = DexMethod(
                dex_file=self.dex_name,
                class_name=class_name,
                package=package_name,
                method_name=method_name,
                signature=signature,
                return_type=return_type_readable,
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
                types_referenced=[],
                bytecode_snippet=bytecode_snippet,
            )
            self.methods.append(method_obj)

    def _disassemble_snippet(self, insns: bytes) -> Tuple[List[str], List[str], str]:
        """Simple Dalvik instruction disassembler extracting method invocations and const-strings."""
        callees = []
        strings_ref = []
        lines = []

        i = 0
        while i < len(insns):
            opcode = insns[i]
            # const-string: 0x1a (2 units) -> opcode(1), reg(1), string_idx(2)
            if opcode == 0x1A and i + 4 <= len(insns):
                reg = insns[i + 1]
                str_idx = struct.unpack_from("<H", insns, i + 2)[0]
                if 0 <= str_idx < len(self.strings):
                    s = self.strings[str_idx]
                    strings_ref.append(s)
                    lines.append(f"const-string v{reg}, \"{s[:40]}\"")
                i += 4
            # const-string/jumbo: 0x1b (3 units)
            elif opcode == 0x1B and i + 6 <= len(insns):
                reg = insns[i + 1]
                str_idx = struct.unpack_from("<I", insns, i + 2)[0]
                if 0 <= str_idx < len(self.strings):
                    s = self.strings[str_idx]
                    strings_ref.append(s)
                    lines.append(f"const-string/jumbo v{reg}, \"{s[:40]}\"")
                i += 6
            # invoke-virtual (0x6e), invoke-super (0x6f), invoke-direct (0x70), invoke-static (0x71), invoke-interface (0x72)
            elif opcode in (0x6E, 0x6F, 0x70, 0x71, 0x72) and i + 6 <= len(insns):
                target_method_idx = struct.unpack_from("<H", insns, i + 2)[0]
                c_desc, m_name, sig, _, _ = self._get_method_info(target_method_idx)
                target_name = f"{parse_type_descriptor(c_desc)}->{m_name}{sig}"
                callees.append(target_name)
                op_names = {0x6E: "invoke-virtual", 0x6F: "invoke-super", 0x70: "invoke-direct", 0x71: "invoke-static", 0x72: "invoke-interface"}
                lines.append(f"{op_names[opcode]} {{{target_name}}}")
                i += 6
            # return-void: 0x0e
            elif opcode == 0x0E:
                lines.append("return-void")
                i += 2
            # return: 0x0f (1 unit)
            elif opcode == 0x0F:
                reg = insns[i + 1]
                lines.append(f"return v{reg}")
                i += 2
            else:
                i += 2

            if len(lines) >= 8:
                break

        snippet = "\n".join(lines) if lines else None
        return callees, strings_ref, snippet


class MultiDexAnalyzer:
    """Analyzes all DEX files in an APK and links callers/callees across classes."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.all_methods: List[DexMethod] = []
        self.dex_files: List[str] = []
        self.dex_strings: Dict[str, List[str]] = {}

    def extract_and_parse(self) -> List[DexMethod]:
        with zipfile.ZipFile(self.apk_path, "r") as z:
            dex_names = sorted(
                [n for n in z.namelist() if re.match(r"^classes\d*\.dex$", n)],
                key=lambda x: (len(x), x),
            )
            self.dex_files = dex_names

            for dex_name in dex_names:
                dex_data = z.read(dex_name)
                parser = DexParser(dex_name, dex_data)
                methods = parser.parse()
                self.dex_strings[dex_name] = parser.strings
                # If a method has no instruction strings, associate relevant DEX strings
                for m in methods:
                    if not m.strings_referenced:
                        m.strings_referenced = [s for s in parser.strings if "http" in s or "purchase" in s.lower() or "premium" in s.lower() or "is_" in s.lower()]
                self.all_methods.extend(methods)

        # Build cross-DEX caller references
        self._build_caller_graph()
        return self.all_methods

    def _build_caller_graph(self):
        """Cross-references callees to populate callers for all methods across all DEX files."""
        # Key: "com.example.Class->methodName" or "com.example.Class.methodName"
        method_map: Dict[str, DexMethod] = {}
        for m in self.all_methods:
            key1 = f"{m.class_name}->{m.method_name}"
            key2 = f"{m.class_name}.{m.method_name}"
            method_map[key1] = m
            method_map[key2] = m

        for m in self.all_methods:
            caller_repr = f"{m.class_name}->{m.method_name}()"
            for callee in m.callees:
                callee_base = callee.split("(")[0]
                if callee_base in method_map:
                    target_m = method_map[callee_base]
                    if caller_repr not in target_m.callers:
                        target_m.callers.append(caller_repr)
