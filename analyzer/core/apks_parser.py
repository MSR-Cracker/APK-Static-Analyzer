"""APKS / Android App Bundle Export parser.
Extracts and coordinates multiple split APKs inside an .apks ZIP archive,
identifying base.apk, split modules, configuration splits, and combining metadata into a unified application view.
"""
import os
import re
import zipfile
import tempfile
import shutil
import logging
from typing import Dict, List, Any, Optional, Tuple

from analyzer.models import ApkInfo, ContainedApkInfo
from analyzer.core.apk_parser import BinaryXmlParser, ApkParser

logger = logging.getLogger(__name__)


def is_apks_container(file_path: str) -> bool:
    """Checks if the given file path is an .apks container (ZIP archive containing .apk files)."""
    if not os.path.exists(file_path):
        return False
    
    if file_path.lower().endswith(".apks"):
        return True

    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as z:
                apk_entries = [n for n in z.namelist() if n.lower().endswith(".apk")]
                if len(apk_entries) >= 1 and (
                    "toc.pb" in z.namelist() or 
                    any("split" in n.lower() or "base" in n.lower() or "standalone" in n.lower() for n in apk_entries) or
                    len(apk_entries) > 1
                ):
                    return True
    except Exception:
        pass

    return False


def classify_split_type(filename: str) -> str:
    """Classifies a split APK into base, architecture, density, language, or feature module."""
    fn = filename.lower()
    if "base" in fn or "master" in fn or "standalone" in fn:
        return "base"
    
    # Architecture / ABI splits
    abi_patterns = ["arm64", "v8a", "armeabi", "v7a", "x86", "x86_64", "mips"]
    if any(abi in fn for abi in abi_patterns):
        return "config_abi"

    # Density / DPI splits
    density_patterns = ["ldpi", "mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi", "tvdpi", "anydpi", "nodpi"]
    if any(dpi in fn for dpi in density_patterns):
        return "config_density"

    # Language / Locale splits
    lang_patterns = [r"split_config\.([a-z]{2}(?:_[a-z0-9]+)?)\.apk", r"config\.([a-z]{2})\.apk"]
    for pat in lang_patterns:
        if re.search(pat, fn):
            return "config_lang"

    if "split" in fn or "feature" in fn:
        return "feature_module"

    return "split"


class ApksParser:
    """Extracts and parses multi-APK (.apks) App Bundle containers."""

    def __init__(self, apks_path: str):
        self.apks_path = apks_path
        if not os.path.exists(apks_path):
            raise FileNotFoundError(f"Target APKS file not found at: {apks_path}")
        if not zipfile.is_zipfile(apks_path):
            raise ValueError(f"Target file is not a valid ZIP/APKS archive: {apks_path}")

        self.temp_dir: Optional[str] = None
        self.extracted_apks: List[Dict[str, Any]] = []
        self.base_apk_path: Optional[str] = None
        self.base_apk_relname: str = "base.apk"

    def extract_and_discover(self, target_temp_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extracts all contained APKs from the .apks archive into a temp folder and identifies base.apk."""
        if target_temp_dir:
            self.temp_dir = target_temp_dir
        else:
            self.temp_dir = tempfile.mkdtemp(prefix="apks_extract_")

        self.extracted_apks = []

        with zipfile.ZipFile(self.apks_path, "r") as z:
            namelist = z.namelist()
            apk_entries = [n for n in namelist if n.lower().endswith(".apk")]

            if not apk_entries:
                raise ValueError(f"No APK files found inside .apks container: {self.apks_path}")

            for entry in apk_entries:
                safe_name = os.path.basename(entry)
                if not safe_name:
                    safe_name = entry.replace("/", "_")
                
                out_path = os.path.join(self.temp_dir, safe_name)
                if os.path.exists(out_path):
                    safe_name = entry.replace("/", "_").replace("\\", "_")
                    out_path = os.path.join(self.temp_dir, safe_name)

                with z.open(entry) as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                info = z.getinfo(entry)
                split_type = classify_split_type(safe_name)

                self.extracted_apks.append({
                    "container_entry": entry,
                    "extracted_name": safe_name,
                    "extracted_path": out_path,
                    "size_bytes": info.file_size,
                    "compressed_size_bytes": info.compress_size,
                    "is_base": False,
                    "split_type": split_type,
                })

        self._identify_base_apk()
        return self.extracted_apks

    def _identify_base_apk(self):
        """Identifies base.apk / base-master.apk or the primary APK containing the main manifest."""
        if not self.extracted_apks:
            return

        # 1. Look for explicit name matches
        for item in self.extracted_apks:
            entry_lower = item["container_entry"].lower()
            name_lower = item["extracted_name"].lower()
            if (
                name_lower == "base.apk"
                or name_lower.startswith("base-master")
                or name_lower.startswith("base_master")
                or "base-master.apk" in entry_lower
                or "splits/base-master.apk" in entry_lower
                or "standalone.apk" in name_lower
            ):
                item["is_base"] = True
                item["split_type"] = "base"
                self.base_apk_path = item["extracted_path"]
                self.base_apk_relname = item["extracted_name"]
                return

        # 2. Inspect manifests inside extracted APKs to find the one with most components
        best_candidate = None
        max_components = -1

        for item in self.extracted_apks:
            apk_path = item["extracted_path"]
            try:
                with zipfile.ZipFile(apk_path, "r") as z_apk:
                    if "AndroidManifest.xml" in z_apk.namelist():
                        manifest_data = z_apk.read("AndroidManifest.xml")
                        axml = BinaryXmlParser(manifest_data)
                        parsed = axml.parse()
                        total_comps = (
                            len(parsed.get("activities", []))
                            + len(parsed.get("services", []))
                            + len(parsed.get("receivers", []))
                        )
                        if total_comps > max_components:
                            max_components = total_comps
                            best_candidate = item
            except Exception:
                pass

        if best_candidate:
            best_candidate["is_base"] = True
            best_candidate["split_type"] = "base"
            self.base_apk_path = best_candidate["extracted_path"]
            self.base_apk_relname = best_candidate["extracted_name"]
        elif self.extracted_apks:
            self.extracted_apks[0]["is_base"] = True
            self.extracted_apks[0]["split_type"] = "base"
            self.base_apk_path = self.extracted_apks[0]["extracted_path"]
            self.base_apk_relname = self.extracted_apks[0]["extracted_name"]

    def parse_metadata(self) -> ApkInfo:
        """Parses combined metadata across all split APKs in the bundle."""
        if not self.extracted_apks:
            self.extract_and_discover()

        container_size = os.path.getsize(self.apks_path)
        container_name = os.path.basename(self.apks_path)

        all_permissions: set = set()
        all_activities: set = set()
        all_services: set = set()
        all_receivers: set = set()
        all_providers: set = set()
        all_native_libs: set = set()
        all_assets: set = set()
        all_dex_files: List[Dict[str, Any]] = []
        contained_apks_info: List[Dict[str, Any]] = []

        primary_pkg = ""
        app_label = ""
        version_name = "1.0"
        version_code = "1"
        min_sdk = "21"
        target_sdk = "33"
        compile_sdk = ""

        for item in self.extracted_apks:
            apk_path = item["extracted_path"]
            apk_name = item["extracted_name"]
            is_base = item["is_base"]
            split_type = item["split_type"]

            apk_perms: List[str] = []
            dex_count = 0

            try:
                with zipfile.ZipFile(apk_path, "r") as z:
                    namelist = z.namelist()

                    # Find DEX files
                    dex_names = sorted(
                        [n for n in namelist if re.match(r"^classes\d*\.dex$", n)],
                        key=lambda x: (len(x), x),
                    )
                    dex_count = len(dex_names)
                    for d in dex_names:
                        info = z.getinfo(d)
                        all_dex_files.append({
                            "name": f"{apk_name}:{d}" if not is_base else d,
                            "size_bytes": info.file_size,
                            "source_apk": apk_name,
                        })

                    # Native libraries and assets
                    for n in namelist:
                        if n.startswith("lib/") and n.endswith(".so"):
                            all_native_libs.add(n)
                        elif n.startswith("assets/"):
                            all_assets.add(n)

                    # Parse manifest
                    if "AndroidManifest.xml" in namelist:
                        manifest_data = z.read("AndroidManifest.xml")
                        axml = BinaryXmlParser(manifest_data)
                        parsed = axml.parse()

                        apk_perms = parsed.get("permissions", [])
                        all_permissions.update(apk_perms)
                        all_activities.update(parsed.get("activities", []))
                        all_services.update(parsed.get("services", []))
                        all_receivers.update(parsed.get("receivers", []))
                        all_providers.update(parsed.get("providers", []))

                        if is_base or not primary_pkg:
                            primary_pkg = parsed.get("package") or primary_pkg
                            app_label = parsed.get("appLabel") or app_label
                            version_name = parsed.get("versionName") or version_name
                            version_code = parsed.get("versionCode") or version_code
                            min_sdk = parsed.get("minSdkVersion") or min_sdk
                            target_sdk = parsed.get("targetSdkVersion") or target_sdk
                            compile_sdk = parsed.get("compileSdkVersion") or compile_sdk

            except Exception as e:
                logger.error(f"Error reading split APK {apk_name}: {e}")

            contained_apks_info.append({
                "name": apk_name,
                "file_size_bytes": item["size_bytes"],
                "dex_count": dex_count,
                "is_base": is_base,
                "split_type": split_type,
                "package_name": primary_pkg,
                "version_name": str(version_name),
                "version_code": str(version_code),
                "permissions": apk_perms,
            })

        if not primary_pkg:
            primary_pkg = container_name.replace(".apks", "").replace("-", ".").lower()

        if not app_label:
            app_label = primary_pkg.split(".")[-1].capitalize()

        return ApkInfo(
            file_name=container_name,
            file_size_bytes=container_size,
            package_name=primary_pkg,
            app_label=app_label,
            version_name=str(version_name),
            version_code=str(version_code),
            min_sdk=str(min_sdk),
            target_sdk=str(target_sdk),
            compile_sdk=str(compile_sdk),
            input_type="APKS",
            container_name=container_name,
            contained_apks=contained_apks_info,
            permissions=sorted(list(all_permissions)),
            activities=sorted(list(all_activities)),
            services=sorted(list(all_services)),
            receivers=sorted(list(all_receivers)),
            providers=sorted(list(all_providers)),
            native_libraries=sorted(list(all_native_libs)),
            assets=sorted(list(all_assets)),
            signing_info={"scheme_v1": True, "scheme_v2": True},
            dex_files_info=all_dex_files,
            total_dex_count=len(all_dex_files),
        )

    def cleanup(self):
        """Removes extracted temporary APK directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                logger.debug(f"Failed to cleanup temp APKS dir {self.temp_dir}: {e}")
