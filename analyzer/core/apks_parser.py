"""APKS / Android App Bundle Export parser.

Extracts and coordinates multiple split APKs inside an .apks ZIP archive.

The parser is intentionally focused on the static-analysis pipeline:

    .apks
      -> contained APKs
      -> identify base APK
      -> identify split/config/feature APKs
      -> expose extracted APK paths
      -> provide unified metadata

It does not perform APK decompilation or purchase detection itself.
"""

import os
import re
import zipfile
import tempfile
import shutil
import logging
from typing import Dict, List, Any, Optional, Set

from analyzer.models import ApkInfo, ContainedApkInfo
from analyzer.core.apk_parser import BinaryXmlParser, ApkParser


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants / helpers
# ---------------------------------------------------------------------------

DEX_NAME_RE = re.compile(
    r"^classes\d*\.dex$",
    re.IGNORECASE,
)

APK_NAME_RE = re.compile(
    r"\.apk$",
    re.IGNORECASE,
)


def _sorted_dex_names(names: List[str]) -> List[str]:
    """Return DEX files in classes.dex, classes2.dex, classes3.dex ... order."""

    def dex_sort_key(name: str):
        base = os.path.basename(name).lower()

        if base == "classes.dex":
            return 1

        match = re.match(
            r"classes(\d+)\.dex$",
            base,
        )

        if match:
            return 1, int(match.group(1))

        return 2, base

    return sorted(names, key=dex_sort_key)


def _safe_extracted_filename(
    archive_entry: str,
    used_names: Set[str],
) -> str:
    """
    Produce a safe unique filename for an APK extracted from an archive.

    APKS archives commonly contain paths such as:

        splits/base-master.apk
        splits/config.arm64_v8a.apk

    We intentionally flatten them because the analyzer only needs actual APK
    files. If two entries have the same basename, a deterministic suffix is
    added instead of overwriting the first APK.
    """

    original_name = os.path.basename(
        archive_entry.replace("\\", "/")
    )

    if not original_name:
        original_name = "contained.apk"

    # Remove characters that are problematic on common filesystems.
    safe_name = re.sub(
        r"[^A-Za-z0-9._+\-]",
        "_",
        original_name,
    )

    if not safe_name.lower().endswith(".apk"):
        safe_name += ".apk"

    candidate = safe_name
    counter = 1

    while candidate.lower() in used_names:
        stem, ext = os.path.splitext(safe_name)
        candidate = f"{stem}_{counter}{ext}"
        counter += 1

    used_names.add(candidate.lower())

    return candidate


def _is_base_name(filename: str) -> bool:
    """Checks whether an APK filename strongly indicates the base APK."""

    name = os.path.basename(filename).lower()

    return name in {
        "base.apk",
        "base-master.apk",
        "base_master.apk",
        "base-master_1.apk",
        "standalone.apk",
    }


def _is_explicit_base_name(filename: str) -> bool:
    """
    Strong base-name check.

    Unlike _is_base_name(), this deliberately excludes standalone.apk because
    standalone APKs should only win when no normal base APK can be identified.
    """

    name = os.path.basename(filename).lower()

    return name in {
        "base.apk",
        "base-master.apk",
        "base_master.apk",
    }


def _manifest_component_score(parsed: Dict[str, Any]) -> int:
    """
    Estimate how likely a manifest is to belong to the main/base APK.

    This is only a fallback. Filename and manifest package information are
    stronger signals.
    """

    activities = parsed.get(
        "activities",
        [],
    )

    services = parsed.get(
        "services",
        [],
    )

    receivers = parsed.get(
        "receivers",
        [],
    )

    providers = parsed.get(
        "providers",
        [],
    )

    permissions = parsed.get(
        "permissions",
        [],
    )

    score = (
        len(activities) * 8
        + len(services) * 4
        + len(receivers) * 3
        + len(providers) * 3
        + len(permissions)
    )

    # An APK with a package name is generally more useful as a base candidate.
    if parsed.get("package"):
        score += 20

    # An APK declaring application label is another useful signal.
    if parsed.get("appLabel"):
        score += 10

    return score


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def is_apks_container(file_path: str) -> bool:
    """
    Checks whether the supplied file is an APKS-like ZIP container.

    A normal APK is also a ZIP, so merely checking for ZIP format is not enough.
    We require at least one contained APK and then use APKS-specific signals.
    """

    if not file_path:
        return False

    if not os.path.isfile(file_path):
        return False

    # Explicit .apks extension is the strongest signal.
    if file_path.lower().endswith(".apks"):
        return True

    try:
        if not zipfile.is_zipfile(file_path):
            return False

        with zipfile.ZipFile(
            file_path,
            "r",
        ) as archive:

            names = archive.namelist()

            apk_entries = [
                name
                for name in names
                if APK_NAME_RE.search(
                    name
                )
            ]

            if not apk_entries:
                return False

            normalized = {
                name.replace("\\", "/").lower()
                for name in names
            }

            # Typical bundletool output.
            if "toc.pb" in normalized:
                return True

            # Multiple APKs strongly indicate an APKS container.
            if len(apk_entries) > 1:
                return True

            # Single contained APK with APKS-like path/name.
            for entry in apk_entries:
                lower = entry.replace(
                    "\\",
                    "/",
                ).lower()

                if (
                    "/splits/" in lower
                    or lower.startswith("splits/")
                    or "standalone.apk" in lower
                    or "base-master.apk" in lower
                    or lower.endswith("/base.apk")
                ):
                    return True

    except (
        OSError,
        zipfile.BadZipFile,
        RuntimeError,
    ) as exc:
        logger.debug(
            "Failed to inspect possible APKS container %s: %s",
            file_path,
            exc,
        )

    return False


def classify_split_type(
    filename: str,
) -> str:
    """
    Classifies a contained APK.

    Possible values:

        base
        config_abi
        config_density
        config_lang
        feature_module
        split
    """

    fn = os.path.basename(
        filename
    ).lower()

    # Base has priority over all other classifications.
    if _is_explicit_base_name(fn):
        return "base"

    if fn == "standalone.apk":
        return "base"

    # ABI / architecture splits.
    abi_patterns = (
        "arm64",
        "arm64-v8a",
        "arm64_v8a",
        "armeabi",
        "armeabi-v7a",
        "armeabi_v7a",
        "v7a",
        "v8a",
        "x86_64",
        "x86-64",
        "x86",
        "mips64",
        "mips",
    )

    if any(
        abi in fn
        for abi in abi_patterns
    ):
        return "config_abi"

    # Density / DPI splits.
    density_patterns = (
        "ldpi",
        "mdpi",
        "hdpi",
        "xhdpi",
        "xxhdpi",
        "xxxhdpi",
        "tvdpi",
        "anydpi",
        "nodpi",
    )

    if any(
        dpi in fn
        for dpi in density_patterns
    ):
        return "config_density"

    # Common language/config names.
    language_patterns = (
        r"(?:^|[._-])"
        r"(?:config[._-])?"
        r"([a-z]{2}(?:[_-][a-z0-9]{2,})?)"
        r"(?:\.apk)$",
        r"split_config\.([a-z]{2}(?:_[a-z0-9]+)?)\.apk",
        r"config\.([a-z]{2})\.apk",
    )

    for pattern in language_patterns:
        if re.search(
            pattern,
            fn,
        ):
            # Avoid treating generic names as language splits.
            if any(
                token in fn
                for token in (
                    "base",
                    "master",
                    "standalone",
                    "feature",
                )
            ):
                continue

            return "config_lang"

    # Feature module indicators.
    if (
        "feature" in fn
        or fn.startswith("split_")
        or fn.startswith("split-")
    ):
        return "feature_module"

    if "split" in fn:
        return "feature_module"

    return "split"


# ---------------------------------------------------------------------------
# APKS parser
# ---------------------------------------------------------------------------

class ApksParser:
    """Extracts and parses multi-APK (.apks) App Bundle containers."""

    def __init__(
        self,
        apks_path: str,
    ):
        self.apks_path = apks_path

        if not os.path.exists(
            apks_path
        ):
            raise FileNotFoundError(
                f"Target APKS file not found at: "
                f"{apks_path}"
            )

        if not os.path.isfile(
            apks_path
        ):
            raise ValueError(
                f"Target APKS path is not a file: "
                f"{apks_path}"
            )

        if not zipfile.is_zipfile(
            apks_path
        ):
            raise ValueError(
                f"Target file is not a valid "
                f"ZIP/APKS archive: {apks_path}"
            )

        self.temp_dir: Optional[str] = None

        self.extracted_apks: List[
            Dict[str, Any]
        ] = []

        self.base_apk_path: Optional[
            str
        ] = None

        self.base_apk_relname: str = (
            "base.apk"
        )

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract_and_discover(
        self,
        target_temp_dir: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Extract all APK files contained in the APKS archive.

        The returned dictionaries intentionally keep the same keys expected by
        MultiDexAnalyzer.
        """

        # If called repeatedly, remove the previous extraction directory when
        # it was created by us.
        if (
            self.temp_dir
            and os.path.exists(self.temp_dir)
            and target_temp_dir != self.temp_dir
        ):
            try:
                shutil.rmtree(
                    self.temp_dir
                )
            except Exception:
                pass

        if target_temp_dir:
            self.temp_dir = os.path.abspath(
                target_temp_dir
            )

            os.makedirs(
                self.temp_dir,
                exist_ok=True,
            )
        else:
            self.temp_dir = tempfile.mkdtemp(
                prefix="apks_extract_"
            )

        self.extracted_apks = []

        used_names: Set[str] = set()

        try:
            with zipfile.ZipFile(
                self.apks_path,
                "r",
            ) as archive:

                apk_entries = [
                    info
                    for info in archive.infolist()
                    if not info.is_dir()
                    and APK_NAME_RE.search(
                        info.filename
                    )
                ]

                if not apk_entries:
                    raise ValueError(
                        "No APK files found inside "
                        f".apks container: "
                        f"{self.apks_path}"
                    )

                # Stable ordering makes analysis reproducible.
                apk_entries.sort(
                    key=lambda info: (
                        info.filename.lower()
                    )
                )

                for info in apk_entries:
                    entry = info.filename

                    safe_name = (
                        _safe_extracted_filename(
                            entry,
                            used_names,
                        )
                    )

                    out_path = os.path.join(
                        self.temp_dir,
                        safe_name,
                    )

                    # Final path containment check.
                    base_dir = os.path.realpath(
                        self.temp_dir
                    )

                    real_out = os.path.realpath(
                        out_path
                    )

                    if not (
                        real_out == base_dir
                        or real_out.startswith(
                            base_dir
                            + os.sep
                        )
                    ):
                        raise RuntimeError(
                            "Unsafe APKS extraction path"
                        )

                    try:
                        with archive.open(
                            info,
                            "r",
                        ) as src, open(
                            out_path,
                            "wb",
                        ) as dst:
                            shutil.copyfileobj(
                                src,
                                dst,
                                length=1024 * 1024,
                            )

                    except Exception as exc:
                        logger.error(
                            "Failed extracting APK "
                            "%s: %s",
                            entry,
                            exc,
                        )
                        continue

                    split_type = (
                        classify_split_type(
                            safe_name
                        )
                    )

                    self.extracted_apks.append(
                        {
                            "container_entry": entry,
                            "extracted_name": safe_name,
                            "extracted_path": out_path,
                            "size_bytes": info.file_size,
                            "compressed_size_bytes": (
                                info.compress_size
                            ),
                            "is_base": False,
                            "split_type": split_type,
                        }
                    )

        except zipfile.BadZipFile as exc:
            raise ValueError(
                "Invalid APKS/ZIP archive: "
                f"{self.apks_path}"
            ) from exc

        self._identify_base_apk()

        # Base first, then deterministic split ordering.
        self.extracted_apks.sort(
            key=lambda item: (
                0 if item.get(
                    "is_base",
                    False,
                ) else 1,
                str(
                    item.get(
                        "split_type",
                        "",
                    )
                ),
                str(
                    item.get(
                        "extracted_name",
                        "",
                    )
                ).lower(),
            )
        )

        return self.extracted_apks

    # -----------------------------------------------------------------------
    # Base APK identification
    # -----------------------------------------------------------------------

    def _identify_base_apk(
        self,
    ):
        """
        Identify the most likely base APK.

        Priority:

        1. Explicit base.apk/base-master.apk.
        2. APK whose manifest looks like the main application.
        3. standalone.apk.
        4. First extracted APK as final fallback.
        """

        if not self.extracted_apks:
            return

        # Reset previous state in case this method is called again.
        for item in self.extracted_apks:
            item["is_base"] = False

        self.base_apk_path = None
        self.base_apk_relname = "base.apk"

        # -------------------------------------------------------------------
        # 1. Strong filename match
        # -------------------------------------------------------------------

        explicit_candidates = [
            item
            for item in self.extracted_apks
            if _is_explicit_base_name(
                item.get(
                    "extracted_name",
                    "",
                )
            )
        ]

        if explicit_candidates:
            # Prefer exact base.apk.
            explicit_candidates.sort(
                key=lambda item: (
                    0
                    if os.path.basename(
                        item.get(
                            "extracted_name",
                            "",
                        )
                    ).lower()
                    == "base.apk"
                    else 1,
                    item.get(
                        "extracted_name",
                        "",
                    ).lower(),
                )
            )

            candidate = (
                explicit_candidates[0]
            )

            self._mark_as_base(
                candidate
            )

            return

        # -------------------------------------------------------------------
        # 2. Manifest-based discovery
        # -------------------------------------------------------------------

        manifest_candidates: List[
            Any
        ] = []

        for item in self.extracted_apks:
            apk_path = item.get(
                "extracted_path"
            )

            if not apk_path:
                continue

            try:
                with zipfile.ZipFile(
                    apk_path,
                    "r",
                ) as apk_archive:

                    manifest_name = (
                        "AndroidManifest.xml"
                    )

                    if (
                        manifest_name
                        not in apk_archive.namelist()
                    ):
                        continue

                    manifest_data = (
                        apk_archive.read(
                            manifest_name
                        )
                    )

                    axml = BinaryXmlParser(
                        manifest_data
                    )

                    parsed = axml.parse()

                    score = (
                        _manifest_component_score(
                            parsed
                        )
                    )

                    package_name = (
                        parsed.get(
                            "package"
                        )
                        or ""
                    )

                    app_label = (
                        parsed.get(
                            "appLabel"
                        )
                        or ""
                    )

                    # Main application manifests generally have both.
                    if package_name:
                        score += 25

                    if app_label:
                        score += 10

                    # Base-like names receive a moderate bonus.
                    name_lower = os.path.basename(
                        item.get(
                            "extracted_name",
                            "",
                        )
                    ).lower()

                    if (
                        "master" in name_lower
                        or "base" in name_lower
                    ):
                        score += 30

                    manifest_candidates.append(
                        (
                            score,
                            package_name,
                            app_label,
                            item,
                            parsed,
                        )
                    )

            except Exception as exc:
                logger.debug(
                    "Failed to inspect manifest "
                    "for %s: %s",
                    item.get(
                        "extracted_name"
                    ),
                    exc,
                )

        if manifest_candidates:
            manifest_candidates.sort(
                key=lambda entry: (
                    entry[0],
                    bool(entry[1]),
                    bool(entry[2]),
                    -len(
                        entry[3].get(
                            "extracted_name",
                            "",
                        )
                    ),
                ),
                reverse=True,
            )

            candidate = (
                manifest_candidates[0][3]
            )

            self._mark_as_base(
                candidate
            )

            return

        # -------------------------------------------------------------------
        # 3. standalone.apk fallback
        # -------------------------------------------------------------------

        standalone = next(
            (
                item
                for item in self.extracted_apks
                if os.path.basename(
                    item.get(
                        "extracted_name",
                        "",
                    )
                ).lower()
                == "standalone.apk"
            ),
            None,
        )

        if standalone:
            self._mark_as_base(
                standalone
            )
            return

        # -------------------------------------------------------------------
        # 4. Final deterministic fallback
        # -------------------------------------------------------------------

        candidate = sorted(
            self.extracted_apks,
            key=lambda item: (
                item.get(
                    "extracted_name",
                    "",
                ).lower()
            ),
        )[0]

        self._mark_as_base(
            candidate
        )

    def _mark_as_base(
        self,
        item: Dict[str, Any],
    ):
        """Mark one extracted APK as the base APK."""

        for other in self.extracted_apks:
            other["is_base"] = (
                other is item
            )

        item["is_base"] = True
        item["split_type"] = "base"

        self.base_apk_path = item.get(
            "extracted_path"
        )

        self.base_apk_relname = item.get(
            "extracted_name",
            "base.apk",
        )

    # -----------------------------------------------------------------------
    # Metadata
    # -----------------------------------------------------------------------

    def parse_metadata(
        self,
    ) -> ApkInfo:
        """Parses combined metadata across all split APKs."""

        if not self.extracted_apks:
            self.extract_and_discover()

        container_size = os.path.getsize(
            self.apks_path
        )

        container_name = os.path.basename(
            self.apks_path
        )

        all_permissions: Set[str] = set()
        all_activities: Set[str] = set()
        all_services: Set[str] = set()
        all_receivers: Set[str] = set()
        all_providers: Set[str] = set()
        all_native_libs: Set[str] = set()
        all_assets: Set[str] = set()

        all_dex_files: List[
            Dict[str, Any]
        ] = []

        contained_apks_info: List[
            Dict[str, Any]
        ] = []

        primary_pkg = ""
        app_label = ""

        version_name = "1.0"
        version_code = "1"

        min_sdk = "21"
        target_sdk = "33"
        compile_sdk = ""

        # -------------------------------------------------------------------
        # Process each contained APK
        # -------------------------------------------------------------------

        for item in self.extracted_apks:
            apk_path = item.get(
                "extracted_path"
            )

            apk_name = item.get(
                "extracted_name",
                "unknown.apk",
            )

            is_base = bool(
                item.get(
                    "is_base",
                    False,
                )
            )

            split_type = item.get(
                "split_type",
                "split",
            )

            apk_perms: List[str] = []
            apk_package = ""
            apk_version_name = ""
            apk_version_code = ""

            dex_count = 0

            if not apk_path:
                logger.warning(
                    "Missing extracted path for %s",
                    apk_name,
                )

                contained_apks_info.append(
                    {
                        "name": apk_name,
                        "file_size_bytes": item.get(
                            "size_bytes",
                            0,
                        ),
                        "dex_count": 0,
                        "is_base": is_base,
                        "split_type": split_type,
                        "package_name": "",
                        "version_name": "",
                        "version_code": "",
                        "permissions": [],
                    }
                )

                continue

            try:
                with zipfile.ZipFile(
                    apk_path,
                    "r",
                ) as archive:

                    names = archive.namelist()

                    # -------------------------------------------------------
                    # DEX
                    # -------------------------------------------------------

                    dex_names = _sorted_dex_names(
                        [
                            name
                            for name in names
                            if DEX_NAME_RE.match(
                                os.path.basename(
                                    name
                                )
                            )
                        ]
                    )

                    dex_count = len(
                        dex_names
                    )

                    for dex_name in dex_names:
                        try:
                            info = archive.getinfo(
                                dex_name
                            )

                            all_dex_files.append(
                                {
                                    "name": (
                                        f"{apk_name}:"
                                        f"{os.path.basename(dex_name)}"
                                        if not is_base
                                        else os.path.basename(
                                            dex_name
                                        )
                                    ),
                                    "size_bytes": (
                                        info.file_size
                                    ),
                                    "source_apk": apk_name,
                                }
                            )

                        except KeyError:
                            logger.debug(
                                "DEX entry disappeared "
                                "while reading %s",
                                dex_name,
                            )

                    # -------------------------------------------------------
                    # Native libraries / assets
                    # -------------------------------------------------------

                    for name in names:
                        normalized = name.replace(
                            "\\",
                            "/",
                        )

                        if (
                            normalized.startswith(
                                "lib/"
                            )
                            and normalized.lower().endswith(
                                ".so"
                            )
                        ):
                            all_native_libs.add(
                                normalized
                            )

                        elif normalized.startswith(
                            "assets/"
                        ):
                            all_assets.add(
                                normalized
                            )

                    # -------------------------------------------------------
                    # AndroidManifest.xml
                    # -------------------------------------------------------

                    manifest_name = (
                        "AndroidManifest.xml"
                    )

                    if (
                        manifest_name
                        in names
                    ):
                        manifest_data = (
                            archive.read(
                                manifest_name
                            )
                        )

                        axml = BinaryXmlParser(
                            manifest_data
                        )

                        parsed = axml.parse()

                        apk_perms = list(
                            parsed.get(
                                "permissions",
                                [],
                            )
                            or []
                        )

                        all_permissions.update(
                            apk_perms
                        )

                        all_activities.update(
                            parsed.get(
                                "activities",
                                [],
                            )
                            or []
                        )

                        all_services.update(
                            parsed.get(
                                "services",
                                [],
                            )
                            or []
                        )

                        all_receivers.update(
                            parsed.get(
                                "receivers",
                                [],
                            )
                            or []
                        )

                        all_providers.update(
                            parsed.get(
                                "providers",
                                [],
                            )
                            or []
                        )

                        apk_package = (
                            parsed.get(
                                "package"
                            )
                            or ""
                        )

                        apk_version_name = str(
                            parsed.get(
                                "versionName"
                            )
                            or ""
                        )

                        apk_version_code = str(
                            parsed.get(
                                "versionCode"
                            )
                            or ""
                        )

                        # ---------------------------------------------------
                        # Primary application metadata
                        #
                        # Base APK always has priority.
                        # ---------------------------------------------------

                        if (
                            is_base
                            or not primary_pkg
                        ):
                            primary_pkg = (
                                apk_package
                                or primary_pkg
                            )

                            app_label = (
                                parsed.get(
                                    "appLabel"
                                )
                                or app_label
                            )

                            version_name = (
                                parsed.get(
                                    "versionName"
                                )
                                or version_name
                            )

                            version_code = (
                                parsed.get(
                                    "versionCode"
                                )
                                or version_code
                            )

                            min_sdk = (
                                parsed.get(
                                    "minSdkVersion"
                                )
                                or min_sdk
                            )

                            target_sdk = (
                                parsed.get(
                                    "targetSdkVersion"
                                )
                                or target_sdk
                            )

                            compile_sdk = (
                                parsed.get(
                                    "compileSdkVersion"
                                )
                                or compile_sdk
                            )

            except zipfile.BadZipFile as exc:
                logger.error(
                    "Invalid contained APK %s: %s",
                    apk_name,
                    exc,
                )

            except Exception as exc:
                logger.error(
                    "Error reading split APK %s: %s",
                    apk_name,
                    exc,
                )

            contained_apks_info.append(
                {
                    "name": apk_name,
                    "file_size_bytes": item.get(
                        "size_bytes",
                        0,
                    ),
                    "dex_count": dex_count,
                    "is_base": is_base,
                    "split_type": split_type,
                    "package_name": (
                        apk_package
                        or primary_pkg
                    ),
                    "version_name": (
                        apk_version_name
                        or str(version_name)
                    ),
                    "version_code": (
                        apk_version_code
                        or str(version_code)
                    ),
                    "permissions": sorted(
                        set(apk_perms)
                    ),
                }
            )

        # -------------------------------------------------------------------
        # Fallback application metadata
        # -------------------------------------------------------------------

        if not primary_pkg:
            primary_pkg = (
                os.path.splitext(
                    container_name
                )[0]
                .replace(
                    "-",
                    ".",
                )
                .lower()
            )

        if not app_label:
            app_label = (
                primary_pkg.split(
                    "."
                )[-1].capitalize()
                if primary_pkg
                else "Application"
            )

        # -------------------------------------------------------------------
        # Return unified model
        # -------------------------------------------------------------------

        return ApkInfo(
            file_name=container_name,
            file_size_bytes=container_size,
            package_name=primary_pkg,
            app_label=app_label,
            version_name=str(
                version_name
            ),
            version_code=str(
                version_code
            ),
            min_sdk=str(
                min_sdk
            ),
            target_sdk=str(
                target_sdk
            ),
            compile_sdk=str(
                compile_sdk
            ),
            input_type="APKS",
            container_name=container_name,
            contained_apks=contained_apks_info,
            permissions=sorted(
                all_permissions
            ),
            activities=sorted(
                all_activities
            ),
            services=sorted(
                all_services
            ),
            receivers=sorted(
                all_receivers
            ),
            providers=sorted(
                all_providers
            ),
            native_libraries=sorted(
                all_native_libs
            ),
            assets=sorted(
                all_assets
            ),

            # Signing information cannot reliably be inferred merely from
            # the APKS container itself. Keep the existing compatibility
            # structure rather than claiming a cryptographic verification.
            signing_info={
                "scheme_v1": None,
                "scheme_v2": None,
            },

            dex_files_info=all_dex_files,
            total_dex_count=len(
                all_dex_files
            ),
        )

    # -----------------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------------

    def cleanup(self):
        """Removes the extracted temporary APK directory."""

        if (
            self.temp_dir
            and os.path.exists(
                self.temp_dir
            )
        ):
            try:
                shutil.rmtree(
                    self.temp_dir
                )
            except Exception as exc:
                logger.debug(
                    "Failed to cleanup temp APKS "
                    "directory %s: %s",
                    self.temp_dir,
                    exc,
                )
            finally:
                self.temp_dir = None
