"""Decompilation manager.

JADX is an optional readability layer.

The analyzer must NEVER depend on JADX for correctness:
Dalvik/Dex bytecode analysis remains the primary source of truth.

Pipeline:

    APK/APKS
       |
       +--> DexParser --------------> ground truth
       |
       +--> JADX (optional) --------> readable Java snippets
"""

import os
import re
import shutil
import subprocess
import logging
from typing import Optional, Dict, List, Tuple


logger = logging.getLogger(__name__)


class Decompiler:
    """Optional JADX manager used only to improve source readability."""

    DEFAULT_TIMEOUT = 180

    def __init__(
        self,
        jadx_path: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.jadx_path = (
            jadx_path
            or shutil.which("jadx")
            or shutil.which("jadx-cli")
        )

        self.timeout = max(
            10,
            int(timeout),
        )

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Return True only when JADX appears executable.

        shutil.which() is preferred because JADX may be available through PATH.
        """

        if not self.jadx_path:
            return False

        path = os.path.abspath(
            self.jadx_path
        )

        return (
            os.path.isfile(path)
            and os.access(
                path,
                os.X_OK,
            )
        )

    # ------------------------------------------------------------------
    # JADX execution
    # ------------------------------------------------------------------

    def decompile(
        self,
        apk_path: str,
        output_dir: str,
    ) -> bool:
        """
        Run JADX against an APK.

        Returns:
            True  -> JADX completed successfully.
            False -> JADX unavailable or failed.

        Failure here is intentionally non-fatal. The DexParser remains
        authoritative.
        """

        if not apk_path:
            logger.warning(
                "JADX skipped: empty APK path."
            )
            return False

        if not os.path.isfile(
            apk_path
        ):
            logger.warning(
                "JADX skipped: APK does not exist: %s",
                apk_path,
            )
            return False

        if not self.is_available():
            logger.info(
                "JADX is not available; "
                "continuing with Dalvik bytecode analysis."
            )
            return False

        try:
            os.makedirs(
                output_dir,
                exist_ok=True,
            )

        except OSError as exc:
            logger.warning(
                "Unable to create JADX output directory "
                "%s: %s",
                output_dir,
                exc,
            )
            return False

        cmd = [
            self.jadx_path,
            "-d",
            output_dir,

            # Source readability.
            "--show-bad-code",

            # Resources are not needed for method analysis.
            "--no-res",

            # Keep comments/metadata useful for static analysis.
            "--comments-level",
            "none",

            apk_path,
        ]

        logger.info(
            "Running JADX on %s",
            os.path.basename(
                apk_path
            ),
        )

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

        except subprocess.TimeoutExpired:
            logger.warning(
                "JADX timed out after %s seconds: %s",
                self.timeout,
                apk_path,
            )
            return False

        except FileNotFoundError:
            logger.warning(
                "JADX executable disappeared or "
                "could not be launched."
            )
            return False

        except PermissionError:
            logger.warning(
                "Permission denied while launching JADX: %s",
                self.jadx_path,
            )
            return False

        except OSError as exc:
            logger.warning(
                "Unable to execute JADX: %s",
                exc,
            )
            return False

        stdout = (
            result.stdout
            or ""
        )

        stderr = (
            result.stderr
            or ""
        )

        if result.returncode == 0:
            logger.info(
                "JADX completed successfully for %s",
                os.path.basename(
                    apk_path
                ),
            )
            return True

        # JADX sometimes produces useful partial output even when returning
        # a non-zero status. Do not treat that as an analyzer failure.
        if self._has_java_sources(
            output_dir
        ):
            logger.warning(
                "JADX returned code %s but generated Java sources. "
                "Partial decompilation will be used.",
                result.returncode,
            )

            if stderr:
                logger.debug(
                    "JADX stderr: %s",
                    stderr[-4000:],
                )

            return True

        logger.warning(
            "JADX failed with return code %s.",
            result.returncode,
        )

        if stderr:
            logger.debug(
                "JADX stderr: %s",
                stderr[-4000:],
            )

        if stdout:
            logger.debug(
                "JADX stdout: %s",
                stdout[-4000:],
            )

        return False

    # ------------------------------------------------------------------
    # Source discovery
    # ------------------------------------------------------------------

    def _has_java_sources(
        self,
        decompiled_dir: str,
    ) -> bool:
        """Check whether JADX produced at least one Java source file."""

        if not decompiled_dir:
            return False

        if not os.path.isdir(
            decompiled_dir
        ):
            return False

        for root, _, files in os.walk(
            decompiled_dir
        ):
            for filename in files:
                if filename.lower().endswith(
                    ".java"
                ):
                    return True

        return False

    def _normalize_class_name(
        self,
        class_name: str,
    ) -> str:
        """
        Normalize a class name into a Java-style dotted name.

        Handles:

            Lcom/example/Foo;
            com/example/Foo
            com.example.Foo
        """

        if not class_name:
            return ""

        value = class_name.strip()

        if value.startswith("L") and value.endswith(";"):
            value = value[1:-1]

        value = value.replace(
            "/",
            ".",
        )

        return value

    def _candidate_source_paths(
        self,
        decompiled_dir: str,
        class_name: str,
    ) -> List[str]:
        """Generate possible JADX source locations."""

        normalized = self._normalize_class_name(
            class_name
        )

        if not normalized:
            return []

        slash_path = normalized.replace(
            ".",
            os.sep,
        )

        basename = os.path.basename(
            slash_path
        )

        candidates = [
            os.path.join(
                decompiled_dir,
                "sources",
                slash_path + ".java",
            ),
            os.path.join(
                decompiled_dir,
                "sources",
                normalized + ".java",
            ),
            os.path.join(
                decompiled_dir,
                slash_path + ".java",
            ),
            os.path.join(
                decompiled_dir,
                normalized + ".java",
            ),

            # JADX commonly places obfuscated/default-package classes here.
            os.path.join(
                decompiled_dir,
                "sources",
                "defpackage",
                basename + ".java",
            ),

            os.path.join(
                decompiled_dir,
                "sources",
                "defpackage",
                "a.java",
            ),
        ]

        # Remove duplicates while preserving order.
        result: List[str] = []
        seen = set()

        for path in candidates:
            normalized_path = os.path.normcase(
                os.path.normpath(
                    path
                )
            )

            if normalized_path not in seen:
                seen.add(
                    normalized_path
                )
                result.append(
                    path
                )

        return result

    def _find_source_file(
        self,
        decompiled_dir: str,
        class_name: str,
    ) -> Optional[str]:
        """
        Locate a Java source file.

        First checks deterministic paths, then falls back to a bounded
        recursive search by filename.
        """

        candidates = self._candidate_source_paths(
            decompiled_dir,
            class_name,
        )

        for path in candidates:
            if os.path.isfile(
                path
            ):
                return path

        normalized = self._normalize_class_name(
            class_name
        )

        if not normalized:
            return None

        expected_basename = (
            normalized.rsplit(
                ".",
                1,
            )[-1]
            + ".java"
        )

        # Anonymous/inner class handling.
        expected_simple = expected_basename

        try:
            for root, _, files in os.walk(
                decompiled_dir
            ):
                for filename in files:
                    if filename == expected_simple:
                        return os.path.join(
                            root,
                            filename,
                        )

        except OSError:
            return None

        return None

    # ------------------------------------------------------------------
    # Source reading
    # ------------------------------------------------------------------

    def _read_source_file(
        self,
        source_path: str,
    ) -> Optional[str]:
        """Read a Java source file safely."""

        try:
            with open(
                source_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                return handle.read()

        except (
            OSError,
            UnicodeError,
        ) as exc:
            logger.debug(
                "Unable to read JADX source %s: %s",
                source_path,
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # Method extraction
    # ------------------------------------------------------------------

    def _method_patterns(
        self,
        method_name: str,
    ) -> List[re.Pattern]:
        """
        Build conservative regex patterns for a method declaration.

        We intentionally allow modifiers/types between the method name and
        opening parenthesis because JADX output varies considerably.
        """

        escaped = re.escape(
            method_name
        )

        return [
            re.compile(
                rf"\b{escaped}\s*\(",
                re.MULTILINE,
            ),

            # Constructors may appear as ClassName(...).
            re.compile(
                rf"\b{escaped}\s*\(",
                re.MULTILINE,
            ),
        ]

    def _find_method_start(
        self,
        source: str,
        method_name: str,
    ) -> Optional[int]:
        """Find the most likely method declaration."""

        if not source or not method_name:
            return None

        # JADX may render special methods differently.
        if method_name in (
            "<init>",
            "<clinit>",
        ):
            # Constructors normally use the class name rather than <init>.
            # The caller should provide the real class name when possible.
            return None

        patterns = self._method_patterns(
            method_name
        )

        best_pos: Optional[int] = None

        for pattern in patterns:
            match = pattern.search(
                source
            )

            if match:
                pos = match.start()

                if (
                    best_pos is None
                    or pos < best_pos
                ):
                    best_pos = pos

        return best_pos

    def _find_matching_brace(
        self,
        source: str,
        opening_brace: int,
    ) -> Optional[int]:
        """
        Find the closing brace matching an opening Java brace.

        This is intentionally a lightweight parser. It handles strings,
        character literals, line comments, and block comments to avoid being
        confused by braces inside them.
        """

        if not (
            0 <= opening_brace
            < len(source)
        ):
            return None

        depth = 0
        i = opening_brace

        in_string = False
        in_char = False
        in_line_comment = False
        in_block_comment = False

        while i < len(source):
            char = source[i]

            next_char = (
                source[i + 1]
                if i + 1 < len(source)
                else ""
            )

            if in_line_comment:
                if char == "\n":
                    in_line_comment = False

                i += 1
                continue

            if in_block_comment:
                if (
                    char == "*"
                    and next_char == "/"
                ):
                    in_block_comment = False
                    i += 2
                    continue

                i += 1
                continue

            if in_string:
                if (
                    char == "\\"
                    and i + 1 < len(source)
                ):
                    i += 2
                    continue

                if char == '"':
                    in_string = False

                i += 1
                continue

            if in_char:
                if (
                    char == "\\"
                    and i + 1 < len(source)
                ):
                    i += 2
                    continue

                if char == "'":
                    in_char = False

                i += 1
                continue

            # Comments.
            if (
                char == "/"
                and next_char == "/"
            ):
                in_line_comment = True
                i += 2
                continue

            if (
                char == "/"
                and next_char == "*"
            ):
                in_block_comment = True
                i += 2
                continue

            # Literals.
            if char == '"':
                in_string = True
                i += 1
                continue

            if char == "'":
                in_char = True
                i += 1
                continue

            # Braces.
            if char == "{":
                depth += 1

            elif char == "}":
                depth -= 1

                if depth == 0:
                    return i

            i += 1

        return None

    def _extract_method_block(
        self,
        source: str,
        method_start: int,
    ) -> Optional[str]:
        """Extract a complete Java method block when possible."""

        if not (
            0 <= method_start
            < len(source)
        ):
            return None

        # Locate the opening brace after the declaration.
        opening_brace = source.find(
            "{",
            method_start,
        )

        # Abstract/interface/native methods may end in ';'.
        semicolon = source.find(
            ";",
            method_start,
        )

        if (
            opening_brace == -1
            or (
                semicolon != -1
                and semicolon < opening_brace
            )
        ):
            end = (
                semicolon + 1
                if semicolon != -1
                else min(
                    len(source),
                    method_start + 500,
                )
            )

            return source[
                method_start:end
            ].strip()

        closing_brace = (
            self._find_matching_brace(
                source,
                opening_brace,
            )
        )

        if closing_brace is None:
            return source[
                method_start:
                min(
                    len(source),
                    method_start + 4000,
                )
            ].strip()

        return source[
            method_start:
            closing_brace + 1
        ].strip()

    # ------------------------------------------------------------------
    # Public source extraction API
    # ------------------------------------------------------------------

    def extract_method_source(
        self,
        decompiled_dir: str,
        class_name: str,
        method_name: str,
        max_chars: int = 12000,
    ) -> Optional[str]:
        """
        Extract a readable method body from JADX output.

        Returns None when source is unavailable.

        This method is only a readability helper. It must not be used as the
        source of truth for detecting purchase logic.
        """

        if not decompiled_dir:
            return None

        if not os.path.isdir(
            decompiled_dir
        ):
            return None

        source_path = self._find_source_file(
            decompiled_dir,
            class_name,
        )

        if not source_path:
            return None

        source = self._read_source_file(
            source_path
        )

        if not source:
            return None

        normalized_method = (
            method_name.strip()
        )

        if not normalized_method:
            return None

        # Handle constructors.
        if normalized_method in (
            "<init>",
            "<clinit>",
        ):
            normalized_class = (
                self._normalize_class_name(
                    class_name
                )
            )

            constructor_name = (
                normalized_class.rsplit(
                    ".",
                    1,
                )[-1]
            )

            method_start = (
                self._find_method_start(
                    source,
                    constructor_name,
                )
            )
        else:
            method_start = (
                self._find_method_start(
                    source,
                    normalized_method,
                )
            )

        if method_start is None:
            return None

        method_source = (
            self._extract_method_block(
                source,
                method_start,
            )
        )

        if not method_source:
            return None

        # Prevent enormous AI-analysis payloads.
        if len(method_source) > max_chars:
            method_source = (
                method_source[
                    :max_chars
                ]
                + "\n/* ... truncated ... */"
            )

        return method_source

    # ------------------------------------------------------------------
    # Batch helpers
    # ------------------------------------------------------------------

    def extract_methods_source(
        self,
        decompiled_dir: str,
        methods: List[Tuple[str, str]],
        max_chars: int = 12000,
    ) -> Dict[str, str]:
        """
        Extract source for multiple methods.

        Input:
            [(class_name, method_name), ...]

        Output:
            {
                "class->method": "source..."
            }
        """

        result: Dict[str, str] = {}

        for class_name, method_name in methods:
            key = (
                f"{class_name}"
                f"->{method_name}"
            )

            source = (
                self.extract_method_source(
                    decompiled_dir,
                    class_name,
                    method_name,
                    max_chars=max_chars,
                )
            )

            if source:
                result[key] = source

        return result
