"""Main entry point for APK-Static-Analyzer pipeline.
Accepts input/app.apk or input/app.apks, performs deep static analysis across all DEX files,
correlates billing & entitlement control flow, generates output/analysis.json and output/report.html.
"""
import os
import sys
import glob
import logging
import argparse
import datetime
from typing import Optional, List, Dict, Any, Set

from analyzer.models import AnalysisReport
from analyzer.core.apk_parser import ApkParser
from analyzer.core.apks_parser import is_apks_container, ApksParser
from analyzer.core.dex_parser import MultiDexAnalyzer
from analyzer.core.cfg_builder import CFGBuilder
from analyzer.core.evidence_collector import EvidenceCollector
from analyzer.detectors.obfuscation_detector import ObfuscationDetector
from analyzer.detectors.billing_detector import BillingDetector
from analyzer.detectors.boolean_detector import BooleanMethodDetector
from analyzer.detectors.verification_locator import BooleanVerificationLocator
from analyzer.detectors.constructor_analyzer import ConstructorAnalyzer
from analyzer.detectors.network_analyzer import NetworkAnalyzer
from analyzer.detectors.classifier import PaymentArchitectureClassifier
from analyzer.detectors.class_analyzer import ClassLevelAnalyzer
from analyzer.ai.gemini_interpreter import GeminiInterpreter
from analyzer.reporters.json_reporter import JsonReporter
from analyzer.reporters.html_reporter import HtmlReporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("APK-Static-Analyzer")


def find_input_file(input_dir: str = "input") -> str:
    """Finds either app.apk or app.apks inside input/ directory, or fails immediately."""
    if not os.path.exists(input_dir):
        logger.error(f"Input directory '{input_dir}' does not exist.")
        sys.exit(1)

    # 1. Check explicit standard names
    explicit_apks = os.path.join(input_dir, "app.apks")
    explicit_apk = os.path.join(input_dir, "app.apk")

    if os.path.isfile(explicit_apks):
        logger.info(f"Discovered APKS target: {explicit_apks}")
        return explicit_apks
    if os.path.isfile(explicit_apk):
        logger.info(f"Discovered APK target: {explicit_apk}")
        return explicit_apk

    # 2. Search for any .apks or .apk inside input/
    apks_files = glob.glob(os.path.join(input_dir, "*.apks"))
    if apks_files:
        logger.info(f"Discovered APKS file: {apks_files[0]}")
        return apks_files[0]

    apk_files = glob.glob(os.path.join(input_dir, "*.apk"))
    if apk_files:
        logger.info(f"Discovered APK file: {apk_files[0]}")
        return apk_files[0]

    logger.error("No valid .apk or .apks file found inside 'input/' directory. Aborting analysis.")
    sys.exit(1)


def run_pipeline(apk_path: str, output_dir: str = "output", enable_gemini: bool = True) -> AnalysisReport:
    """Runs the full static analysis pipeline programmatically on a target APK or APKS file."""
    is_apks = is_apks_container(apk_path)
    logger.info(f"Analyzing Target: {apk_path} (Type: {'APKS (Split Bundle)' if is_apks else 'Standard APK'})")

    apks_parser: Optional[ApksParser] = None
    extracted_apks: Optional[List[Dict[str, Any]]] = None

    try:
        # 1. Parse container metadata
        if is_apks:
            apks_parser = ApksParser(apk_path)
            extracted_apks = apks_parser.extract_and_discover()
            apk_info = apks_parser.parse_metadata()
        else:
            parser = ApkParser(apk_path)
            apk_info = parser.parse()

        # 2. Parse DEX files and bytecode
        dex_analyzer = MultiDexAnalyzer(apk_path, extracted_apks=extracted_apks)
        all_methods = dex_analyzer.extract_and_parse()

        # 3. Detectors
        obfuscation = ObfuscationDetector(all_methods).detect()
        billing = BillingDetector(all_methods).detect()
        boolean_candidates = BooleanMethodDetector(all_methods).detect()
        verif_locations, call_sites = BooleanVerificationLocator(all_methods, boolean_candidates).detect()
        constructors = ConstructorAnalyzer(all_methods).detect()
        endpoints = NetworkAnalyzer(all_methods).detect()
        classification = PaymentArchitectureClassifier(
            billing=billing,
            boolean_candidates=boolean_candidates,
            endpoints=endpoints,
            constructors=constructors,
            verification_locations=verif_locations,
            call_sites=call_sites,
        ).classify()
        class_analysis = ClassLevelAnalyzer(all_methods, billing, boolean_candidates, constructors).analyze()

        # 4. CFGs
        cfgs = []
        cfg_sigs: Set[str] = set()
        
        # Build CFG for methods with verification locations / call sites
        for vl in verif_locations:
            for m in all_methods:
                if m.class_name == vl.class_name and m.method_name == vl.method_name and m.signature == vl.method_signature:
                    sig = f"{m.class_name}->{m.method_name}{m.signature}"
                    if sig not in cfg_sigs:
                        cfg = CFGBuilder.build_for_method(m)
                        if cfg:
                            cfgs.append(cfg)
                            cfg_sigs.add(sig)

        # Build CFG for boolean candidates with bytecode
        for cand in boolean_candidates[:6]:
            for m in all_methods:
                if m.class_name == cand.class_name and m.method_name == cand.method_name and m.dex_file == cand.dex_file:
                    sig = f"{m.class_name}->{m.method_name}{m.signature}"
                    if sig not in cfg_sigs:
                        cfg = CFGBuilder.build_for_method(m)
                        if cfg:
                            cfgs.append(cfg)
                            cfg_sigs.add(sig)

        # 5. Collect Evidence & Numbered IDs
        collector = EvidenceCollector()
        evidence_list = collector.collect(
            billing=billing,
            boolean_candidates=boolean_candidates,
            verification_locations=verif_locations,
            call_sites=call_sites,
            constructors=constructors,
            endpoints=endpoints,
            obfuscation=obfuscation,
            classification=classification,
            class_analysis=class_analysis,
        )
        evidence_package = collector.build_gemini_evidence_package(
            package_name=apk_info.package_name if apk_info else "",
            input_type=apk_info.input_type if apk_info else "APK",
            total_dex=len(dex_analyzer.dex_files),
            classification=classification,
            class_analysis=class_analysis,
        )

        # 6. Quality & Limitations
        unsupported_total = dex_analyzer.unsupported_opcodes_total
        methods_with_code = [m for m in all_methods if m.instructions]
        if not methods_with_code and all_methods:
            analysis_quality = "LIMITED"
            warnings = ["DEX files contain class definitions without parsed bytecode instructions or code items."]
        elif unsupported_total:
            analysis_quality = "PARTIAL"
            warnings = [f"Encountered {len(unsupported_total)} unsupported/partial opcodes during disassembly."]
        else:
            analysis_quality = "FULL"
            warnings = []

        if obfuscation.status.value == "YES":
            warnings.append("Code is obfuscated (ProGuard/R8). Names and identifiers may be shortened or stripped.")

        limitations = [
            "Static analysis alone cannot capture runtime dynamic code loading (DexClassLoader) or native JNI integrity checks without instrumentation.",
            "Backend server-side API responses require valid network credentials and active runtime communication to observe live payload schemas."
        ]

        # 7. Report object
        report = AnalysisReport(
            analysis_timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            apk_info=apk_info,
            input_type=apk_info.input_type if apk_info else "APK",
            container_name=apk_info.container_name if apk_info else os.path.basename(apk_path),
            contained_apks=apk_info.contained_apks if apk_info else [],
            dex_files=dex_analyzer.dex_files,
            obfuscation=obfuscation,
            billing=billing,
            classification=classification,
            class_analysis=class_analysis,
            boolean_candidates=boolean_candidates,
            boolean_verification_locations=verif_locations,
            call_sites=call_sites,
            constructors=constructors,
            network_endpoints=endpoints,
            evidence_inventory=evidence_list,
            cfgs=cfgs,
            ai_reasoning=None,
            analysis_status="COMPLETED",
            analysis_quality=analysis_quality,
            unsupported_opcodes_detected=unsupported_total,
            warnings_or_errors=warnings,
            limitations=limitations,
        )

        # 8. AI Reasoning
        if enable_gemini:
            gemini = GeminiInterpreter()
            report.ai_reasoning = gemini.interpret(report, evidence_package)
        else:
            gemini = GeminiInterpreter(api_key=None)
            report.ai_reasoning = gemini._generate_fallback_reasoning(report)

        # 9. Generate outputs
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, "analysis.json")
        html_path = os.path.join(output_dir, "report.html")

        JsonReporter(report, output_path=json_path).generate()
        HtmlReporter(report, output_path=html_path).generate()

        return report

    finally:
        if apks_parser:
            apks_parser.cleanup()


def main():
    parser = argparse.ArgumentParser(description="Deep APK/APKS Static Analysis Pipeline")
    parser.add_argument("--apk", dest="apk_path", help="Path to target .apk or .apks file (defaults to finding in input/)")
    parser.add_argument("--output-dir", dest="output_dir", default="output", help="Directory where analysis.json and report.html are written")
    parser.add_argument("--gemini", dest="enable_gemini", action="store_true", default=True, help="Enable Gemini AI Reasoning")
    parser.add_argument("--no-gemini", dest="enable_gemini", action="store_false", help="Disable Gemini AI Reasoning")
    args = parser.parse_args()

    logger.info("=== Starting Deep APK/APKS Static Analysis ===")
    target_apk = args.apk_path or find_input_file()
    run_pipeline(target_apk, output_dir=args.output_dir, enable_gemini=args.enable_gemini)
    logger.info(f"=== Analysis Completed. Results saved to {args.output_dir}/ ===")


if __name__ == "__main__":
    main()
