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
    """Pure-Python Android Binary XML (AXML) parser for AndroidManifest.xml."""

    RES_NULL_TYPE = 0x0000
    RES_STRING_POOL_TYPE = 0x0001
    RES_XML_TYPE = 0x0003

    RES_XML_START_NAMESPACE_TYPE = 0x0100
    RES_XML_END_NAMESPACE_TYPE = 0x0101
    RES_XML_START_ELEMENT_TYPE = 0x0102
    RES_XML_END_ELEMENT_TYPE = 0x0103

    # TypedValue formats
    TYPE_NULL = 0x00
    TYPE_REFERENCE = 0x01
    TYPE_ATTRIBUTE = 0x02
    TYPE_STRING = 0x03
    TYPE_FLOAT = 0x04
    TYPE_DIMENSION = 0x05
    TYPE_FRACTION = 0x06
    TYPE_FIRST_INT = 0x10
    TYPE_INT_DEC = 0x10
    TYPE_INT_HEX = 0x11
    TYPE_INT_BOOLEAN = 0x12
    TYPE_LAST_INT = 0x1F

    def __init__(self, data: bytes):
        self.data = data
        self.cursor = 0
        self.string_pool: List[str] = []

    def parse(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "package": "",
            "appLabel": "",
            "versionCode": "",
            "versionName": "",
            "minSdkVersion": "",
            "targetSdkVersion": "",
            "compileSdkVersion": "",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        if len(self.data) < 8:
            return result

        try:
            header_type, header_size, file_size = struct.unpack_from(
                "<HHI", self.data, 0
            )

            if header_type != self.RES_XML_TYPE:
                return self._fallback_regex_parse()

            if file_size > len(self.data):
                file_size = len(self.data)

            if header_size < 8 or header_size > file_size:
                return self._fallback_regex_parse()

            self.cursor = header_size

            while self.cursor + 8 <= file_size:
                chunk_type, chunk_header_size, chunk_size = struct.unpack_from(
                    "<HHI", self.data, self.cursor
                )

                if chunk_size < chunk_header_size or chunk_size < 8:
                    break

                if self.cursor + chunk_size > file_size:
                    break

                if chunk_type == self.RES_STRING_POOL_TYPE:
                    self._parse_string_pool(self.cursor)

                elif chunk_type == self.RES_XML_START_ELEMENT_TYPE:
                    self._parse_element(self.cursor, result)

                self.cursor += chunk_size

        except Exception as e:
            logger.debug(
                f"AXML parsing exception: {e}, falling back to regex extraction"
            )
            return self._fallback_regex_parse()

        # Regex fallback is used only to fill missing fields.
        fallback = self._fallback_regex_parse()

        for key, value in fallback.items():
            if not result.get(key):
                result[key] = value

        return result

    # ------------------------------------------------------------------
    # String pool
    # ------------------------------------------------------------------

    @staticmethod
    def _read_utf8_length(data: bytes, offset: int):
        """
        Reads Android's variable-length UTF-8 string length.

        Returns:
            (length, next_offset)
        """
        if offset >= len(data):
            return 0, offset

        first = data[offset]

        if first & 0x80:
            if offset + 1 >= len(data):
                return 0, len(data)

            length = ((first & 0x7F) << 8) | data[offset + 1]
            return length, offset + 2

        return first, offset + 1

    @staticmethod
    def _read_utf16_length(data: bytes, offset: int):
        """
        Reads Android's variable-length UTF-16 string length.
        """
        if offset + 1 >= len(data):
            return 0, offset

        first = struct.unpack_from("<H", data, offset)[0]

        if first & 0x8000:
            if offset + 3 >= len(data):
                return 0, len(data)

            second = struct.unpack_from("<H", data, offset + 2)[0]
            length = ((first & 0x7FFF) << 16) | second
            return length, offset + 4

        return first, offset + 2

    def _parse_string_pool(self, offset: int):
        try:
            if offset + 28 > len(self.data):
                return

            (
                _chunk_type,
                header_size,
                chunk_size,
                string_count,
                style_count,
                flags,
                strings_start,
                styles_start,
            ) = struct.unpack_from("<HHIIIIII", self.data, offset)

            if string_count <= 0:
                self.string_pool = []
                return

            is_utf8 = bool(flags & (1 << 8))

            indices_offset = offset + header_size
            pool_base = offset + strings_start

            if (
                indices_offset < 0
                or pool_base < 0
                or indices_offset + string_count * 4 > len(self.data)
                or pool_base > len(self.data)
            ):
                return

            string_indices = [
                struct.unpack_from(
                    "<I",
                    self.data,
                    indices_offset + i * 4
                )[0]
                for i in range(string_count)
            ]

            parsed_strings: List[str] = []

            for str_idx in string_indices:
                str_offset = pool_base + str_idx

                if str_offset < 0 or str_offset >= len(self.data):
                    parsed_strings.append("")
                    continue

                if is_utf8:
                    # UTF-8 strings contain:
                    #   UTF-16 length
                    #   UTF-8 byte length
                    #   UTF-8 bytes
                    #   NUL
                    _, pos = self._read_utf8_length(
                        self.data,
                        str_offset
                    )

                    _, pos = self._read_utf8_length(
                        self.data,
                        pos
                    )

                    end = self.data.find(b"\x00", pos)

                    if end == -1:
                        end = min(len(self.data), pos + 65536)

                    raw = self.data[pos:end]

                    parsed_strings.append(
                        raw.decode("utf-8", errors="replace")
                    )

                else:
                    # UTF-16LE strings contain a variable-length
                    # UTF-16 character count followed by UTF-16LE data.
                    length, pos = self._read_utf16_length(
                        self.data,
                        str_offset
                    )

                    end = pos + length * 2

                    if end > len(self.data):
                        end = len(self.data)

                    raw = self.data[pos:end]

                    parsed_strings.append(
                        raw.decode("utf-16le", errors="replace")
                    )

            self.string_pool = parsed_strings

        except Exception as e:
            logger.debug(f"Error parsing string pool: {e}")

    def _get_string(self, idx: int) -> str:
        if 0 <= idx < len(self.string_pool):
            return self.string_pool[idx]
        return ""

    # ------------------------------------------------------------------
    # Typed XML values
    # ------------------------------------------------------------------

    def _decode_typed_value(
        self,
        raw_value: str,
        value_type: int,
        value_data: int
    ) -> str:
        """
        Converts an AXML TypedValue into a useful string representation.
        """

        if raw_value:
            return raw_value

        if value_type == self.TYPE_STRING:
            return self._get_string(value_data)

        if value_type == self.TYPE_INT_BOOLEAN:
            return "true" if value_data != 0 else "false"

        if value_type == self.TYPE_INT_DEC:
            return str(value_data)

        if value_type == self.TYPE_INT_HEX:
            return f"0x{value_data:08x}"

        if value_type == self.TYPE_REFERENCE:
            return f"@0x{value_data:08x}"

        if value_type == self.TYPE_ATTRIBUTE:
            return f"?0x{value_data:08x}"

        if value_type == self.TYPE_FLOAT:
            try:
                value = struct.unpack("<f", struct.pack("<I", value_data))[0]
                return str(value)
            except Exception:
                return str(value_data)

        return str(value_data)

    # ------------------------------------------------------------------
    # XML elements
    # ------------------------------------------------------------------

    def _parse_element(
        self,
        offset: int,
        result: Dict[str, Any]
    ):
        try:
            if offset + 36 > len(self.data):
                return

            (
                _line_number,
                _comment,
                _namespace_idx,
                name_idx,
                attr_start,
                attr_size,
                attr_count,
                _id_index,
                _class_index,
                _style_index,
            ) = struct.unpack_from(
                "<IIIIHHHHHH",
                self.data,
                offset + 8
            )

            tag_name = self._get_string(name_idx)

            if not tag_name:
                return

            attrs: Dict[str, str] = {}

            # attrStart is relative to the START_ELEMENT chunk's
            # attribute structure beginning.
            attr_offset = offset + 8 + attr_start

            if attr_size < 20:
                attr_size = 20

            for i in range(attr_count):
                curr_attr_offset = attr_offset + i * attr_size

                if curr_attr_offset + 20 > len(self.data):
                    break

                (
                    _namespace_idx,
                    attr_name_idx,
                    raw_value_idx,
                    val_size,
                    val_res_type,
                    val_data,
                ) = struct.unpack_from(
                    "<IIIBBI",
                    self.data,
                    curr_attr_offset
                )

                attr_name = self._get_string(attr_name_idx)
                raw_value = self._get_string(raw_value_idx)

                if not attr_name:
                    continue

                decoded_value = self._decode_typed_value(
                    raw_value,
                    val_res_type,
                    val_data
                )

                attrs[attr_name] = decoded_value

            # ----------------------------------------------------------
            # Manifest
            # ----------------------------------------------------------

            if tag_name == "manifest":
                result["package"] = attrs.get(
                    "package",
                    result["package"]
                )

                result["versionCode"] = attrs.get(
                    "versionCode",
                    result["versionCode"]
                )

                result["versionName"] = attrs.get(
                    "versionName",
                    result["versionName"]
                )

                if attrs.get("compileSdkVersion"):
                    result["compileSdkVersion"] = attrs[
                        "compileSdkVersion"
                    ]

            # ----------------------------------------------------------
            # Application
            # ----------------------------------------------------------

            elif tag_name == "application":
                label = attrs.get("label", "")

                # Resource labels such as @string/app_name cannot be
                # resolved without resources. Preserve the raw reference
                # only if no literal label was available.
                if label and not label.startswith("@"):
                    result["appLabel"] = label

            # ----------------------------------------------------------
            # SDK
            # ----------------------------------------------------------

            elif tag_name == "uses-sdk":
                min_sdk = attrs.get("minSdkVersion", "")
                target_sdk = attrs.get("targetSdkVersion", "")

                if min_sdk:
                    result["minSdkVersion"] = min_sdk

                if target_sdk:
                    result["targetSdkVersion"] = target_sdk

            # ----------------------------------------------------------
            # Permissions
            # ----------------------------------------------------------

            elif tag_name == "uses-permission":
                perm = (
                    attrs.get("name")
                    or attrs.get("permission")
                    or ""
                )

                if perm and perm not in result["permissions"]:
                    result["permissions"].append(perm)

            # ----------------------------------------------------------
            # Components
            # ----------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def _fallback_regex_parse(self) -> Dict[str, Any]:
        text = self.data.decode("latin-1", errors="ignore")

        result: Dict[str, Any] = {
            "package": "",
            "appLabel": "",
            "versionCode": "",
            "versionName": "",
            "minSdkVersion": "",
            "targetSdkVersion": "",
            "compileSdkVersion": "",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        # Package name
        pkg_match = re.search(
            r"package[\x00\s:=]+([a-zA-Z0-9_.]+)",
            text
        )

        if pkg_match:
            result["package"] = pkg_match.group(1)
        else:
            pkg_alt = re.findall(
                r"\b([a-z][a-z0-9_]*(?:\.[a-zA-Z0-9_]+)+)\b",
                text
            )

            if pkg_alt:
                result["package"] = pkg_alt[0]

        # Version
        version_code = re.search(
            r"versionCode[\x00\s:=]+([0-9]+)",
            text
        )

        if version_code:
            result["versionCode"] = version_code.group(1)

        version_name = re.search(
            r"versionName[\x00\s:=]+([a-zA-Z0-9._+\-]+)",
            text
        )

        if version_name:
            result["versionName"] = version_name.group(1)

        # SDK
        min_sdk = re.search(
            r"minSdkVersion[\x00\s:=]+([0-9]+)",
            text
        )

        target_sdk = re.search(
            r"targetSdkVersion[\x00\s:=]+([0-9]+)",
            text
        )

        compile_sdk = re.search(
            r"compileSdkVersion[\x00\s:=]+([0-9]+)",
            text
        )

        if min_sdk:
            result["minSdkVersion"] = min_sdk.group(1)

        if target_sdk:
            result["targetSdkVersion"] = target_sdk.group(1)

        if compile_sdk:
            result["compileSdkVersion"] = compile_sdk.group(1)

        # Permissions
        perms = re.findall(
            r"(?:android\.permission\.[A-Z0-9_]+|"
            r"com\.android\.vending\.[A-Za-z0-9_.]+)",
            text
        )

        result["permissions"] = sorted(set(perms))

        # Activities
        acts = re.findall(
            r"\b([a-zA-Z0-9_.$]+(?:Activity|MainActivity|"
            r"LauncherActivity))\b",
            text
        )

        result["activities"] = sorted(set(acts))

        # Services
        services = re.findall(
            r"\b([a-zA-Z0-9_.$]+Service)\b",
            text
        )

        result["services"] = sorted(set(services))

        # Receivers
        receivers = re.findall(
            r"\b([a-zA-Z0-9_.$]+Receiver)\b",
            text
        )

        result["receivers"] = sorted(set(receivers))

        # Providers
        providers = re.findall(
            r"\b([a-zA-Z0-9_.$]+Provider)\b",
            text
        )

        result["providers"] = sorted(set(providers))

        return result


class ApkParser:
    """Extracts high-level APK metadata, SDK versions, DEX files,
    component lists, native libraries, assets, and signing information.
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path

        if not os.path.exists(apk_path):
            raise FileNotFoundError(
                f"APK file not found at: {apk_path}"
            )

        if not zipfile.is_zipfile(apk_path):
            raise ValueError(
                f"Target file is not a valid APK/ZIP archive: {apk_path}"
            )

    # ------------------------------------------------------------------
    # Signing detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_signing_schemes(z: zipfile.ZipFile) -> Dict[str, Any]:
        """
        Detects APK signing evidence.

        v1:
            META-INF/*.RSA / *.DSA / *.EC / *.SF

        v2/v3/v4:
            Android APK Signing Block immediately before ZIP central
            directory.

        This is detection only; it does not verify cryptographic validity.
        """

        names = z.namelist()

        v1_files = [
            name
            for name in names
            if name.upper().startswith("META-INF/")
            and (
                name.upper().endswith(".RSA")
                or name.upper().endswith(".DSA")
                or name.upper().endswith(".EC")
                or name.upper().endswith(".SF")
            )
        ]

        has_v1 = bool(v1_files)

        has_v2_or_newer = False
        signing_block_size = 0

        try:
            # APK Signing Block is immediately before the ZIP EOCD.
            raw = z.fp

            if raw is not None and hasattr(raw, "seek"):
                raw.seek(0, os.SEEK_END)
                file_size = raw.tell()

                # EOCD minimum size is 22 bytes.
                if file_size >= 22:
                    search_size = min(file_size, 65557)
                    raw.seek(file_size - search_size)

                    tail = raw.read(search_size)

                    eocd_rel = tail.rfind(b"PK\x05\x06")

                    if eocd_rel >= 0 and eocd_rel + 22 <= len(tail):
                        eocd_abs = (
                            file_size
                            - search_size
                            + eocd_rel
                        )

                        # Central directory offset is at EOCD + 16.
                        central_dir_offset = struct.unpack_from(
                            "<I",
                            tail,
                            eocd_rel + 16
                        )[0]

                        if (
                            central_dir_offset >= 24
                            and central_dir_offset <= file_size
                        ):
                            raw.seek(central_dir_offset - 24)

                            footer = raw.read(24)

                            if (
                                len(footer) == 24
                                and footer[8:24]
                                == b"APK Sig Block 42"
                            ):
                                block_size = struct.unpack_from(
                                    "<Q",
                                    footer,
                                    0
                                )[0]

                                block_start = (
                                    central_dir_offset
                                    - block_size
                                    - 8
                                )

                                if block_start >= 0:
                                    raw.seek(block_start)
                                    header = raw.read(8)

                                    if len(header) == 8:
                                        header_size = struct.unpack(
                                            "<Q",
                                            header
                                        )[0]

                                        if header_size == block_size:
                                            has_v2_or_newer = True
                                            signing_block_size = (
                                                block_size
                                            )

        except Exception as e:
            logger.debug(
                f"Unable to inspect APK Signing Block: {e}"
            )

        return {
            "scheme_v1": has_v1,
            "scheme_v2": has_v2_or_newer,
            "scheme_v3": has_v2_or_newer,
            "scheme_v4": False,
            "v1_signature_files": sorted(v1_files),
            "signing_block_size": signing_block_size,
            "cryptographically_verified": False,
        }

    # ------------------------------------------------------------------
    # Main parser
    # ------------------------------------------------------------------

    def parse(self) -> ApkInfo:
        from analyzer.core.apks_parser import (
            is_apks_container,
            ApksParser,
        )

        if is_apks_container(self.apk_path):
            apks_parser = ApksParser(self.apk_path)

            try:
                apks_parser.extract_and_discover()
                return apks_parser.parse_metadata()
            finally:
                apks_parser.cleanup()

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

        pkg_name = ""
        app_label = ""
        version_name = "1.0"
        version_code = "1"
        min_sdk = "21"
        target_sdk = "33"
        compile_sdk = ""

        signing_info: Dict[str, Any] = {}

        with zipfile.ZipFile(self.apk_path, "r") as z:
            namelist = z.namelist()

            # ----------------------------------------------------------
            # DEX
            # ----------------------------------------------------------

            dex_names = sorted(
                [
                    n
                    for n in namelist
                    if re.match(
                        r"^classes\d*\.dex$",
                        n
                    )
                ],
                key=lambda x: (
                    len(x),
                    x
                ),
            )

            for dex_name in dex_names:
                info = z.getinfo(dex_name)

                dex_files_info.append(
                    {
                        "name": dex_name,
                        "size_bytes": info.file_size,
                        "source_apk": file_name,
                    }
                )

            # ----------------------------------------------------------
            # Native libraries
            # ----------------------------------------------------------

            native_libs = sorted(
                [
                    n
                    for n in namelist
                    if n.startswith("lib/")
                    and n.endswith(".so")
                ]
            )

            # ----------------------------------------------------------
            # Assets
            # ----------------------------------------------------------

            assets = sorted(
                [
                    n
                    for n in namelist
                    if n.startswith("assets/")
                ]
            )

            # ----------------------------------------------------------
            # Signing
            # ----------------------------------------------------------

            signing_info = self._detect_signing_schemes(z)

            # ----------------------------------------------------------
            # AndroidManifest.xml
            # ----------------------------------------------------------

            if "AndroidManifest.xml" in namelist:
                try:
                    manifest_data = z.read(
                        "AndroidManifest.xml"
                    )

                    axml = BinaryXmlParser(
                        manifest_data
                    )

                    parsed = axml.parse()

                    pkg_name = (
                        parsed.get("package")
                        or pkg_name
                    )

                    app_label = (
                        parsed.get("appLabel")
                        or app_label
                    )

                    version_name = (
                        parsed.get("versionName")
                        or version_name
                    )

                    version_code = (
                        parsed.get("versionCode")
                        or version_code
                    )

                    min_sdk = (
                        parsed.get("minSdkVersion")
                        or min_sdk
                    )

                    target_sdk = (
                        parsed.get("targetSdkVersion")
                        or target_sdk
                    )

                    compile_sdk = (
                        parsed.get("compileSdkVersion")
                        or compile_sdk
                    )

                    permissions = parsed.get(
                        "permissions",
                        []
                    )

                    activities = parsed.get(
                        "activities",
                        []
                    )

                    services = parsed.get(
                        "services",
                        []
                    )

                    receivers = parsed.get(
                        "receivers",
                        []
                    )

                    providers = parsed.get(
                        "providers",
                        []
                    )

                except Exception as e:
                    logger.warning(
                        f"Error parsing AndroidManifest.xml: {e}"
                    )

        # --------------------------------------------------------------
        # Final fallbacks
        # --------------------------------------------------------------

        if not pkg_name:
            pkg_name = (
                file_name
                .rsplit(".", 1)[0]
                .replace("-", ".")
                .lower()
            )

        if not app_label:
            app_label = pkg_name.split(".")[-1].capitalize()

        # Normalize lists
        permissions = sorted(set(permissions))
        activities = sorted(set(activities))
        services = sorted(set(services))
        receivers = sorted(set(receivers))
        providers = sorted(set(providers))

        contained_apk = {
            "name": file_name,
            "file_size_bytes": file_size,
            "dex_count": len(dex_files_info),
            "is_base": True,
            "split_type": "base",
            "package_name": pkg_name,
            "version_name": str(version_name),
            "version_code": str(version_code),
            "permissions": permissions,
        }

        return ApkInfo(
            file_name=file_name,
            file_size_bytes=file_size,
            package_name=pkg_name,
            app_label=app_label,
            version_name=str(version_name),
            version_code=str(version_code),
            min_sdk=str(min_sdk),
            target_sdk=str(target_sdk),
            compile_sdk=str(compile_sdk),
            input_type="APK",
            container_name=file_name,
            contained_apks=[contained_apk],
            permissions=permissions,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers,
            native_libraries=native_libs,
            assets=assets,
            signing_info=signing_info,
            dex_files_info=dex_files_info,
            total_dex_count=len(dex_files_info),
        )
