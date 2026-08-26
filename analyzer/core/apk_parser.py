"""Core APK parser for extracting manifest, components, resources, assets, and certificate info."""
import os
import zipfile
import struct
import re
import logging
from typing import Dict, List, Any, Optional
from analyzer.models import ApkInfo

logger = logging.getLogger(__name__)


class BinaryXmlParser:
    """Pure-Python minimal Android Binary XML (AXML) parser for AndroidManifest.xml."""

    RES_NULL_TYPE = 0x0000
    RES_STRING_POOL_TYPE = 0x0001
    RES_XML_TYPE = 0x0003
    RES_XML_START_ELEMENT_TYPE = 0x0102
    RES_XML_END_ELEMENT_TYPE = 0x0103
    RES_XML_START_NAMESPACE_TYPE = 0x0100
    RES_XML_END_NAMESPACE_TYPE = 0x0101

    def __init__(self, data: bytes):
        self.data = data
        self.cursor = 0
        self.string_pool: List[str] = []

    def parse(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "package": "",
            "versionCode": "",
            "versionName": "",
            "minSdkVersion": "",
            "targetSdkVersion": "",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        if len(self.data) < 8:
            return result

        try:
            header_type, header_size, file_size = struct.unpack_from("<HHI", self.data, 0)
            if header_type != self.RES_XML_TYPE:
                return self._fallback_regex_parse()
            
            self.cursor = header_size
            while self.cursor < len(self.data):
                chunk_type, chunk_header_size, chunk_size = struct.unpack_from("<HHI", self.data, self.cursor)
                if chunk_size == 0:
                    break

                if chunk_type == self.RES_STRING_POOL_TYPE:
                    self._parse_string_pool(self.cursor)
                elif chunk_type == self.RES_XML_START_ELEMENT_TYPE:
                    self._parse_element(self.cursor, result)

                self.cursor += chunk_size
        except Exception as e:
            logger.debug(f"AXML parsing exception: {e}, falling back to regex extraction")
            return self._fallback_regex_parse()

        # If key fields missed, augment with regex
        fallback = self._fallback_regex_parse()
        for k, v in fallback.items():
            if not result.get(k):
                result[k] = v

        return result

    def _parse_string_pool(self, offset: int):
        try:
            _, header_size, _, string_count, style_count, flags, strings_start, _ = struct.unpack_from(
                "<HHIIIIII", self.data, offset
            )
            is_utf8 = bool(flags & (1 << 8))

            indices_offset = offset + header_size
            string_indices = [
                struct.unpack_from("<I", self.data, indices_offset + i * 4)[0]
                for i in range(string_count)
            ]

            pool_base = offset + strings_start
            self.string_pool = []
            for str_idx in string_indices:
                str_offset = pool_base + str_idx
                if is_utf8:
                    # UTF-8 encoded
                    if str_offset >= len(self.data):
                        self.string_pool.append("")
                        continue
                    # Skip length bytes
                    s_len_val = self.data[str_offset]
                    start = str_offset + (2 if s_len_val & 0x80 else 1)
                    end = self.data.find(b"\x00", start)
                    if end == -1 or end > start + 1024:
                        end = start + 64
                    self.string_pool.append(self.data[start:end].decode("utf-8", errors="ignore"))
                else:
                    # UTF-16LE encoded
                    if str_offset + 2 > len(self.data):
                        self.string_pool.append("")
                        continue
                    s_len = struct.unpack_from("<H", self.data, str_offset)[0]
                    start = str_offset + 2
                    end = start + s_len * 2
                    self.string_pool.append(self.data[start:end].decode("utf-16le", errors="ignore"))
        except Exception as e:
            logger.debug(f"Error parsing string pool: {e}")

    def _get_string(self, idx: int) -> str:
        if 0 <= idx < len(self.string_pool):
            return self.string_pool[idx]
        return ""

    def _parse_element(self, offset: int, result: Dict[str, Any]):
        try:
            # Struct: line_number(4), comment(4), ns(4), name_idx(4), attr_start(2), attr_size(2), attr_count(2), id_idx(2), class_idx(2), style_idx(2)
            _, _, _, name_idx, attr_start, attr_size, attr_count, _, _, _ = struct.unpack_from(
                "<IIIIHHHHHH", self.data, offset + 8
            )
            tag_name = self._get_string(name_idx)
            attrs: Dict[str, Any] = {}

            attr_offset = offset + 8 + attr_start
            for i in range(attr_count):
                curr_attr_offset = attr_offset + i * attr_size
                if curr_attr_offset + 20 > len(self.data):
                    break
                _, attr_name_idx, raw_val_idx, val_size, val_res_type, val_data = struct.unpack_from(
                    "<IIIBBI", self.data, curr_attr_offset
                )
                attr_name = self._get_string(attr_name_idx)
                raw_val = self._get_string(raw_val_idx)
                attrs[attr_name] = raw_val or str(val_data)

            if tag_name == "manifest":
                result["package"] = attrs.get("package", result["package"])
                result["versionCode"] = attrs.get("versionCode", result["versionCode"])
                result["versionName"] = attrs.get("versionName", result["versionName"])
            elif tag_name == "uses-sdk":
                result["minSdkVersion"] = attrs.get("minSdkVersion", result["minSdkVersion"])
                result["targetSdkVersion"] = attrs.get("targetSdkVersion", result["targetSdkVersion"])
            elif tag_name == "uses-permission":
                perm = attrs.get("name", "")
                if perm and perm not in result["permissions"]:
                    result["permissions"].append(perm)
            elif tag_name == "activity":
                name = attrs.get("name", "")
                if name and name not in result["activities"]:
                    result["activities"].append(name)
            elif tag_name == "service":
                name = attrs.get("name", "")
                if name and name not in result["services"]:
                    result["services"].append(name)
            elif tag_name == "receiver":
                name = attrs.get("name", "")
                if name and name not in result["receivers"]:
                    result["receivers"].append(name)
            elif tag_name == "provider":
                name = attrs.get("name", "")
                if name and name not in result["providers"]:
                    result["providers"].append(name)
        except Exception as e:
            logger.debug(f"Element parse error: {e}")

    def _fallback_regex_parse(self) -> Dict[str, Any]:
        """Regex string extractor from raw binary/text bytes."""
        text = self.data.decode("latin-1", errors="ignore")
        result: Dict[str, Any] = {
            "package": "",
            "versionCode": "",
            "versionName": "",
            "minSdkVersion": "",
            "targetSdkVersion": "",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        # Package regex
        pkg_match = re.search(r"package\x00([a-zA-Z0-9_.]+)", text)
        if pkg_match:
            result["package"] = pkg_match.group(1)
        else:
            # Common package pattern
            pkg_alt = re.findall(r"([a-z][a-z0-9_]*\.[a-z0-9_.]+[a-z0-9_])", text)
            if pkg_alt:
                result["package"] = pkg_alt[0]

        # Permissions
        perms = re.findall(r"(android\.permission\.[A-Z_]+|com\.android\.vending\.[A-Z_]+)", text)
        result["permissions"] = sorted(list(set(perms)))

        # Components
        acts = re.findall(r"([a-zA-Z0-9_.]+(?:Activity|MainActivity|LauncherActivity))", text)
        result["activities"] = sorted(list(set(acts)))

        return result


class ApkParser:
    """Extracts high-level APK metadata, certificates, assets, and identifies all DEX files."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found at: {apk_path}")

    def parse(self) -> ApkInfo:
        file_size = os.path.getsize(self.apk_path)
        file_name = os.path.basename(self.apk_path)

        permissions: List[str] = []
        activities: List[str] = []
        services: List[str] = []
        receivers: List[str] = []
        providers: List[str] = []
        native_libs: List[str] = []
        assets: List[str] = []
        dex_files_info: List[Dict[str, Any]] = []
        signing_info: Dict[str, Any] = {"scheme_v1": False, "scheme_v2": False, "certificates": []}

        pkg_name = ""
        version_name = "1.0"
        version_code = "1"
        min_sdk = "21"
        target_sdk = "33"

        with zipfile.ZipFile(self.apk_path, "r") as z:
            namelist = z.namelist()

            # Identify DEX files and their sizes
            dex_names = sorted(
                [n for n in namelist if re.match(r"^classes\d*\.dex$", n)],
                key=lambda x: (len(x), x),
            )
            for dex_name in dex_names:
                info = z.getinfo(dex_name)
                dex_files_info.append({
                    "name": dex_name,
                    "size_bytes": info.file_size,
                    "compressed_size_bytes": info.compress_size,
                })

            # Identify Native libraries
            for n in namelist:
                if n.startswith("lib/") and n.endswith(".so"):
                    native_libs.append(n)
                elif n.startswith("assets/"):
                    assets.append(n)
                elif n.startswith("META-INF/") and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC")):
                    signing_info["scheme_v1"] = True
                    signing_info["certificates"].append(n)

            # Parse AndroidManifest.xml
            if "AndroidManifest.xml" in namelist:
                try:
                    manifest_data = z.read("AndroidManifest.xml")
                    axml = BinaryXmlParser(manifest_data)
                    parsed = axml.parse()
                    pkg_name = parsed.get("package", "")
                    version_name = parsed.get("versionName", "1.0") or "1.0"
                    version_code = parsed.get("versionCode", "1") or "1"
                    min_sdk = parsed.get("minSdkVersion", "21") or "21"
                    target_sdk = parsed.get("targetSdkVersion", "33") or "33"
                    permissions = parsed.get("permissions", [])
                    activities = parsed.get("activities", [])
                    services = parsed.get("services", [])
                    receivers = parsed.get("receivers", [])
                    providers = parsed.get("providers", [])
                except Exception as e:
                    logger.warning(f"Failed to parse AndroidManifest.xml: {e}")

        # Fallback if package name is empty
        if not pkg_name:
            pkg_name = os.path.splitext(file_name)[0]

        return ApkInfo(
            file_name=file_name,
            file_size_bytes=file_size,
            package_name=pkg_name,
            version_name=str(version_name),
            version_code=str(version_code),
            min_sdk=str(min_sdk),
            target_sdk=str(target_sdk),
            permissions=permissions,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers,
            native_libraries=native_libs,
            assets=assets[:50],  # cap to top 50
            signing_info=signing_info,
            dex_files_info=dex_files_info,
            total_dex_count=len(dex_files_info),
        )
