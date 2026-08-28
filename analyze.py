"""Main entry point for APK-Static-Analyzer pipeline.

Accepts input/app.apk or input/app.apks and performs deep static analysis
across all DEX files.

Pipeline:
    APK/APKS
      -> APK metadata
      -> multi-DEX parsing
      -> billing detection
      -> boolean candidate detection
      -> boolean call-site / branch verification
      -> constructor analysis
      -> network analysis
      -> architecture classification
      -> class-level analysis
      -> CFG construction
      -> evidence collection
      -> optional AI reasoning
      -> analysis.json / report.html
"""

import os
import sys
import glob
import logging
import argparse
import datetime
from typing import Optional, List, Dict, Any, Set, Tuple

from analyzer.models import (
    AnalysisReport,
    DexMethod,
)

from analyzer.core.apk_parser import ApkParser
from analyzer.core.apks_parser import (
    is_apks_container,
    ApksParser,
)

from analyzer.core.dex_parser import MultiDexAnalyzer
from analyzer.core.cfg_builder import CFGBuilder
from analyzer.core.evidence_collector import EvidenceCollector

from analyzer.detectors.obfuscation_detector import (
    ObfuscationDetector,
)

from analyzer.detectors.billing_detector import (
    BillingDetector,
)

from analyzer.detectors.boolean_detector import (
    BooleanMethodDetector,
)

from analyzer.detectors.verification_locator import (
    BooleanVerificationLocator,
)

from analyzer.detectors.constructor_analyzer import (
    ConstructorAnalyzer,
)

from analyzer.detectors.network_analyzer import (
    NetworkAnalyzer,
)

from analyzer.detectors.classifier import (
    PaymentArchitectureClassifier,
)

from analyzer.detectors.class_analyzer import (
    ClassLevelAnalyzer,
)

from analyzer.ai.gemini_interpreter import (
    GeminiInterpreter,
)

from analyzer.reporters.json_reporter import (
    JsonReporter,
)

from analyzer.reporters.html_reporter import (
    HtmlReporter,
)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(
    "APK-Static-Analyzer"
)


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

def find_input_file(
    input_dir: str = "input",
) -> str:
    """Find an APK/APKS target inside the input directory.

    Priority:
        1. input/app.apks
        2. input/app.apk
        3. first *.apks
        4. first *.apk
    """

    if not os.path.isdir(input_dir):
        logger.error(
            "Input directory '%s' does not exist.",
            input_dir,
        )
        sys.exit(1)

    explicit_apks = os.path.join(
        input_dir,
        "app.apks",
    )

    explicit_apk = os.path.join(
        input_dir,
        "app.apk",
    )

    if os.path.isfile(explicit_apks):
        logger.info(
            "Discovered APKS target: %s",
            explicit_apks,
        )
        return explicit_apks

    if os.path.isfile(explicit_apk):
        logger.info(
            "Discovered APK target: %s",
            explicit_apk,
        )
        return explicit_apk

    apks_files = sorted(
        glob.glob(
            os.path.join(
                input_dir,
                "*.apks",
            )
        )
    )

    if apks_files:
        logger.info(
            "Discovered APKS file: %s",
            apks_files[0],
        )
        return apks_files[0]

    apk_files = sorted(
        glob.glob(
            os.path.join(
                input_dir,
                "*.apk",
            )
        )
    )

    if apk_files:
        logger.info(
            "Discovered APK file: %s",
            apk_files[0],
        )
        return apk_files[0]

    logger.error(
        "No valid .apk or .apks file found inside '%s'.",
        input_dir,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Method indexing helpers
# ---------------------------------------------------------------------------

def _method_signature(
    method: DexMethod,
) -> str:
    """Return canonical method signature."""

    return (
        f"{method.class_name}"
        f"->{method.method_name}"
        f"{method.signature}"
    )


def _method_base(
    method: DexMethod,
) -> str:
    """Return class + method without prototype."""

    return (
        f"{method.class_name}"
        f"->{method.method_name}"
    )


def _build_method_index(
    methods: List[DexMethod],
) -> Dict[str, List[DexMethod]]:
    """Build a collision-safe method index.

    A list is kept for every key because the same class/method name can
    theoretically appear in different DEX files or with different
    signatures.
    """

    index: Dict[str, List[DexMethod]] = {}

    for method in methods:
        keys = {
            _method_signature(method),
            _method_base(method),
        }

        # DEX-qualified key avoids collisions across split APKs.
        dex_key = (
            f"{method.source_apk}:"
            f"{method.dex_file}:"
            f"{_method_signature(method)}"
        )

        keys.add(dex_key)

        for key in keys:
            index.setdefault(
                key,
                [],
            ).append(method)

    return index


def _find_method_for_candidate(
    candidate: Any,
    methods: List[DexMethod],
    method_index: Dict[str, List[DexMethod]],
) -> Optional[DexMethod]:
    """Resolve a BooleanMethodCandidate to its original DexMethod.

    Matching priority:
        1. exact DEX + class + method + signature
        2. exact class + method + signature
        3. class + method + DEX
        4. class + method
    """

    exact = (
        f"{candidate.class_name}"
        f"->{candidate.method_name}"
        f"{candidate.signature}"
    )

    dex_key = (
        f"{candidate.source_apk}:"
        f"{candidate.dex_file}:"
        f"{exact}"
    )

    for key in (
        dex_key,
        exact,
    ):
        matches = method_index.get(
            key,
            [],
        )

        if matches:
            return matches[0]

    for method in methods:
        if (
            method.class_name
            == candidate.class_name
            and method.method_name
            == candidate.method_name
            and method.signature
            == candidate.signature
            and method.dex_file
            == candidate.dex_file
        ):
            return method

    for method in methods:
        if (
            method.class_name
            == candidate.class_name
            and method.method_name
            == candidate.method_name
        ):
            return method

    return None


def _find_method_for_verification(
    location: Any,
    methods: List[DexMethod],
    method_index: Dict[str, List[DexMethod]],
) -> Optional[DexMethod]:
    """Resolve a BooleanVerificationLocation to its method."""

    exact = (
        f"{location.class_name}"
        f"->{location.method_name}"
        f"{location.method_signature}"
    )

    matches = method_index.get(
        exact,
        [],
    )

    # Prefer the same DEX/source APK.
    for method in matches:
        if (
            method.dex_file == location.dex_file
            and method.source_apk == location.source_apk
        ):
            return method

    if matches:
        return matches[0]

    for method in methods:
        if (
            method.class_name
            == location.class_name
            and method.method_name
            == location.method_name
            and method.signature
            == location.method_signature
            and method.dex_file
            == location.dex_file
        ):
            return method

    return None


# ---------------------------------------------------------------------------
# CFG construction
# ---------------------------------------------------------------------------

def _build_relevant_cfgs(
    methods: List[DexMethod],
    boolean_candidates: List[Any],
    verification_locations: List[Any],
    call_sites: List[Any],
) -> List[Any]:
    """Build CFGs for methods relevant to purchase/entitlement analysis.

    Unlike the previous implementation, this does not arbitrarily restrict
    Boolean candidates to the first six results.

    Priority is given to:
        - verified boolean gate locations
        - boolean call sites
        - boolean candidates
    """

    cfgs: List[Any] = []

    method_index = _build_method_index(
        methods
    )

    selected: Dict[str, DexMethod] = {}

    # 1. Verified branch locations.
    for location in verification_locations:
        method = _find_method_for_verification(
            location,
            methods,
            method_index,
        )

        if method:
            selected[
                _method_signature(method)
            ] = method

    # 2. Call sites.
    for call_site in call_sites:
        exact = (
            f"{call_site.caller_class}"
            f"->{call_site.caller_method}"
            f"{call_site.caller_signature}"
        )

        matches = method_index.get(
            exact,
            [],
        )

        for method in matches:
            if (
                method.dex_file
                == call_site.dex_file
                and method.source_apk
                == call_site.source_apk
            ):
                selected[
                    _method_signature(method)
                ] = method
                break

    # 3. Boolean candidates.
    for candidate in boolean_candidates:
        method = _find_method_for_candidate(
            candidate,
            methods,
            method_index,
        )

        if method:
            selected[
                _method_signature(method)
            ] = method

    # Build CFG once per method.
    for signature, method in selected.items():
        try:
            cfg = CFGBuilder.build_for_method(
                method
            )

            if cfg:
                cfgs.append(
                    cfg
                )

        except Exception as exc:
            logger.warning(
                "CFG construction failed for %s: %s",
                signature,
                exc,
            )

    return cfgs


# ---------------------------------------------------------------------------
# Quality assessment
# ---------------------------------------------------------------------------

def _calculate_analysis_quality(
    methods: List[DexMethod],
    unsupported_opcodes: List[Dict[str, Any]],
) -> Tuple[str, List[str]]:
    """Calculate overall static-analysis quality."""

    warnings: List[str] = []

    methods_with_code = [
        method
        for method in methods
        if method.instructions
    ]

    if methods and not methods_with_code:
        warnings.append(
            "DEX files contain class/method definitions "
            "but no parsed bytecode instructions or code items."
        )

        return (
            "LIMITED",
            warnings,
        )

    if unsupported_opcodes:
        warnings.append(
            "Encountered "
            f"{len(unsupported_opcodes)} "
            "unsupported or partially decoded opcodes "
            "during DEX disassembly."
        )

        return (
            "PARTIAL",
            warnings,
        )

    return (
        "FULL",
        warnings,
    )


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    apk_path: str,
    output_dir: str = "output",
    enable_gemini: bool = True,
) -> AnalysisReport:
    """Run the complete APK/APKS static-analysis pipeline."""

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(
            f"Target APK/APKS not found: {apk_path}"
        )

    is_apks = is_apks_container(
        apk_path
    )

    logger.info(
        "Analyzing target: %s (Type: %s)",
        apk_path,
        "APKS (Split Bundle)"
        if is_apks
        else "Standard APK",
    )

    apks_parser: Optional[
        ApksParser
    ] = None

    extracted_apks: Optional[
        List[Dict[str, Any]]
    ] = None

    try:
        # ---------------------------------------------------------------
        # 1. APK/APKS metadata
        # ---------------------------------------------------------------

        logger.info(
            "Step 1/9: Parsing APK metadata..."
        )

        if is_apks:
            apks_parser = ApksParser(
                apk_path
            )

            extracted_apks = (
                apks_parser.extract_and_discover()
            )

            apk_info = (
                apks_parser.parse_metadata()
            )

        else:
            parser = ApkParser(
                apk_path
            )

            apk_info = parser.parse()

        # ---------------------------------------------------------------
        # 2. Multi-DEX parsing
        # ---------------------------------------------------------------

        logger.info(
            "Step 2/9: Parsing all DEX files..."
        )

        dex_analyzer = MultiDexAnalyzer(
            apk_path,
            extracted_apks=extracted_apks,
        )

        all_methods = (
            dex_analyzer.extract_and_parse()
        )

        logger.info(
            "Parsed %d methods across %d DEX files.",
            len(all_methods),
            len(dex_analyzer.dex_files),
        )

        # ---------------------------------------------------------------
        # 3. Static detectors
        # ---------------------------------------------------------------

        logger.info(
            "Step 3/9: Running detectors..."
        )

        obfuscation = (
            ObfuscationDetector(
                all_methods
            ).detect()
        )

        billing = (
            BillingDetector(
                all_methods
            ).detect()
        )

        boolean_candidates = (
            BooleanMethodDetector(
                all_methods
            ).detect()
        )

        logger.info(
            "Boolean candidates detected: %d",
            len(boolean_candidates),
        )

        # ---------------------------------------------------------------
        # 4. Boolean verification
        # ---------------------------------------------------------------

        logger.info(
            "Step 4/9: Tracing boolean verification call sites..."
        )

        verification_locator = (
            BooleanVerificationLocator(
                all_methods,
                boolean_candidates,
            )
        )

        (
            verification_locations,
            call_sites,
        ) = verification_locator.detect()

        logger.info(
            "Verification locations: %d; call sites: %d",
            len(verification_locations),
            len(call_sites),
        )

        # ---------------------------------------------------------------
        # 5. Remaining detectors
        # ---------------------------------------------------------------

        constructors = (
            ConstructorAnalyzer(
                all_methods
            ).detect()
        )

        endpoints = (
            NetworkAnalyzer(
                all_methods
            ).detect()
        )

        classification = (
            PaymentArchitectureClassifier(
                billing=billing,
                boolean_candidates=boolean_candidates,
                endpoints=endpoints,
                constructors=constructors,
                verification_locations=verification_locations,
                call_sites=call_sites,
            ).classify()
        )

        class_analysis = (
            ClassLevelAnalyzer(
                all_methods,
                billing,
                boolean_candidates,
                constructors,
            ).analyze()
        )

        # ---------------------------------------------------------------
        # 6. CFGs
        # ---------------------------------------------------------------

        logger.info(
            "Step 5/9: Building relevant control-flow graphs..."
        )

        cfgs = _build_relevant_cfgs(
            methods=all_methods,
            boolean_candidates=boolean_candidates,
            verification_locations=verification_locations,
            call_sites=call_sites,
        )

        logger.info(
            "Built %d CFGs.",
            len(cfgs),
        )

        # ---------------------------------------------------------------
        # 7. Evidence collection
        # ---------------------------------------------------------------

        logger.info(
            "Step 6/9: Collecting evidence..."
        )

        collector = EvidenceCollector()

        evidence_list = collector.collect(
            billing=billing,
            boolean_candidates=boolean_candidates,
            verification_locations=verification_locations,
            call_sites=call_sites,
            constructors=constructors,
            endpoints=endpoints,
            obfuscation=obfuscation,
            classification=classification,
            class_analysis=class_analysis,
        )

        evidence_package = (
            collector.build_gemini_evidence_package(
                package_name=(
                    apk_info.package_name
                    if apk_info
                    else ""
                ),
                input_type=(
                    apk_info.input_type
                    if apk_info
                    else "APK"
                ),
                total_dex=len(
                    dex_analyzer.dex_files
                ),
                classification=classification,
                class_analysis=class_analysis,
            )
        )

        # ---------------------------------------------------------------
        # 8. Quality / warnings / report
        # ---------------------------------------------------------------

        logger.info(
            "Step 7/9: Calculating analysis quality..."
        )

        unsupported_total = (
            dex_analyzer.unsupported_opcodes_total
        )

        (
            analysis_quality,
            warnings,
        ) = _calculate_analysis_quality(
            all_methods,
            unsupported_total,
        )

        if (
            getattr(
                obfuscation,
                "status",
                None,
            ) is not None
            and obfuscation.status.value
            == "YES"
        ):
            warnings.append(
                "Code appears to be obfuscated "
                "(ProGuard/R8). Names and identifiers "
                "may be shortened or stripped."
            )

        if not billing.providers_detected:
            warnings.append(
                "No recognized commercial billing SDK was "
                "detected. Purchase logic may be custom, "
                "server-driven, obfuscated, or implemented "
                "through another library."
            )

        if (
            boolean_candidates
            and not verification_locations
        ):
            warnings.append(
                "Boolean entitlement candidates were found, "
                "but no candidate was conclusively linked to "
                "a conditional branch at a discovered call site."
            )

        limitations = [
            (
                "Static analysis alone cannot reliably capture "
                "runtime dynamic code loading such as DexClassLoader "
                "or dynamically generated bytecode."
            ),
            (
                "Native JNI implementations may require separate "
                "native-code analysis or runtime instrumentation."
            ),
            (
                "Server-side purchase validation cannot be fully "
                "reconstructed from static APK/APKS analysis alone."
            ),
            (
                "Obfuscation, reflection, dynamic dispatch, and "
                "generated code can reduce method and call-site "
                "resolution accuracy."
            ),
        ]

        # ---------------------------------------------------------------
        # 9. Build report
        # ---------------------------------------------------------------

        logger.info(
            "Step 8/9: Building analysis report..."
        )

        report = AnalysisReport(
            analysis_timestamp=(
                datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()
            ),

            apk_info=apk_info,

            input_type=(
                apk_info.input_type
                if apk_info
                else (
                    "APKS"
                    if is_apks
                    else "APK"
                )
            ),

            container_name=(
                apk_info.container_name
                if apk_info
                else os.path.basename(
                    apk_path
                )
            ),

            contained_apks=(
                apk_info.contained_apks
                if apk_info
                else []
            ),

            apk={
                "path": apk_path,
                "input_type": (
                    "APKS"
                    if is_apks
                    else "APK"
                ),
            },

            dex_files=dex_analyzer.dex_files,

            obfuscation=obfuscation,

            billing=billing,

            classification=classification,

            class_analysis=class_analysis,

            boolean_candidates=boolean_candidates,

            boolean_verification_locations=(
                verification_locations
            ),

            call_sites=call_sites,

            constructors=constructors,

            network_endpoints=endpoints,

            evidence_inventory=evidence_list,

            cfgs=cfgs,

            ai_reasoning=None,

            analysis_status="COMPLETED",

            analysis_quality=analysis_quality,

            unsupported_opcodes_detected=(
                unsupported_total
            ),

            warnings_or_errors=warnings,

            limitations=limitations,
        )

        # ---------------------------------------------------------------
        # AI reasoning
        # ---------------------------------------------------------------

        logger.info(
            "Step 9/9: Generating reasoning..."
        )

        if enable_gemini:
            try:
                gemini = GeminiInterpreter()

                report.ai_reasoning = (
                    gemini.interpret(
                        report,
                        evidence_package,
                    )
                )

            except Exception as exc:
                logger.warning(
                    "Gemini reasoning failed: %s",
                    exc,
                )

                warnings.append(
                    f"AI reasoning failed: {exc}"
                )

                # Keep static analysis successful even if AI fails.
                try:
                    fallback = GeminiInterpreter(
                        api_key=None
                    )

                    report.ai_reasoning = (
                        fallback._generate_fallback_reasoning(
                            report
                        )
                    )

                except Exception as fallback_exc:
                    logger.warning(
                        "Fallback reasoning failed: %s",
                        fallback_exc,
                    )

        else:
            try:
                fallback = GeminiInterpreter(
                    api_key=None
                )

                report.ai_reasoning = (
                    fallback._generate_fallback_reasoning(
                        report
                    )
                )

            except Exception as exc:
                logger.warning(
                    "Fallback reasoning failed: %s",
                    exc,
                )

        # ---------------------------------------------------------------
        # Output
        # ---------------------------------------------------------------

        os.makedirs(
            output_dir,
            exist_ok=True,
        )

        json_path = os.path.join(
            output_dir,
            "analysis.json",
        )

        html_path = os.path.join(
            output_dir,
            "report.html",
        )

        JsonReporter(
            report,
            output_path=json_path,
        ).generate()

        HtmlReporter(
            report,
            output_path=html_path,
        ).generate()

        logger.info(
            "Analysis JSON written to: %s",
            json_path,
        )

        logger.info(
            "HTML report written to: %s",
            html_path,
        )

        return report

    except Exception as exc:
        logger.exception(
            "Fatal analysis pipeline error: %s",
            exc,
        )
        raise

    finally:
        if apks_parser is not None:
            try:
                apks_parser.cleanup()
            except Exception as exc:
                logger.debug(
                    "Failed to cleanup APKS extraction directory: %s",
                    exc,
                )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""

    parser = argparse.ArgumentParser(
        description=(
            "Deep APK/APKS Static Analysis Pipeline"
        )
    )

    parser.add_argument(
        "--apk",
        dest="apk_path",
        help=(
            "Path to target .apk or .apks file. "
            "Defaults to input/app.apk or input/app.apks."
        ),
    )

    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default="output",
        help=(
            "Directory where analysis.json and "
            "report.html are written."
        ),
    )

    parser.add_argument(
        "--gemini",
        dest="enable_gemini",
        action="store_true",
        help="Enable Gemini AI reasoning.",
    )

    parser.add_argument(
        "--no-gemini",
        dest="enable_gemini",
        action="store_false",
        help="Disable Gemini AI reasoning.",
    )

    # Default to enabled while allowing --no-gemini to disable it.
    parser.set_defaults(
        enable_gemini=True
    )

    args = parser.parse_args()

    logger.info(
        "=============================================="
    )
    logger.info(
        "Starting Deep APK/APKS Static Analysis"
    )
    logger.info(
        "=============================================="
    )

    target_apk = (
        args.apk_path
        or find_input_file()
    )

    logger.info(
        "Target: %s",
        target_apk,
    )

    report = run_pipeline(
        target_apk,
        output_dir=args.output_dir,
        enable_gemini=args.enable_gemini,
    )

    logger.info(
        "=============================================="
    )

    logger.info(
        "Analysis completed successfully."
    )

    logger.info(
        "Status: %s",
        report.analysis_status,
    )

    logger.info(
        "Quality: %s",
        report.analysis_quality,
    )

    logger.info(
        "DEX files: %d",
        len(report.dex_files),
    )

    logger.info(
        "Methods: %d",
        len(
            report.boolean_candidates
        ),
    )

    logger.info(
        "Verified boolean gates: %d",
        len(
            report.boolean_verification_locations
        ),
    )

    logger.info(
        "Output directory: %s",
        args.output_dir,
    )

    logger.info(
        "=============================================="
    )


if __name__ == "__main__":
    main()
