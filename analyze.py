#!/usr/bin/env python3
"""APK-Static-Analyzer CLI Entry Point.
Performs deterministic multi-DEX static analysis, in-app purchase detection,
boolean method discovery, constructor inspection, and generates analysis.json & report.html.
"""

import os
import sys
import argparse
import logging
from typing import Dict, Any, List

from analyzer.models import (
    AnalysisReport, Confidence, ClassificationType, StatusState
)
from analyzer.core.apk_parser import ApkParser
from analyzer.core.dex_parser import MultiDexAnalyzer
from analyzer.core.decompiler import Decompiler
from analyzer.core.callgraph import PaymentCallGraphBuilder
from analyzer.detectors.billing_detector import BillingDetector
from analyzer.detectors.boolean_detector import PurchaseBooleanDetector
from analyzer.detectors.constructor_analyzer import ConstructorAnalyzer
from analyzer.detectors.network_analyzer import NetworkAnalyzer
from analyzer.detectors.classifier import PaymentArchitectureClassifier
from analyzer.ai.gemini_interpreter import GeminiInterpreter
from analyzer.reporters.json_reporter import JsonReporter
from analyzer.reporters.html_reporter import HtmlReporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("APK-Analyzer")


def run_pipeline(
    apk_path: str,
    output_dir: str = "output",
    enable_gemini: bool = False,
    gemini_api_key: str = None,
    jadx_path: str = None,
) -> AnalysisReport:
    """Executes the full static analysis pipeline on an APK."""
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Starting Static Analysis on target: {apk_path}")

    warnings_errors: List[str] = []
    status = "COMPLETED"

    # 1. Parse APK Manifest & Metadata
    logger.info("[1/7] Extracting Manifest, SDK, permissions, and DEX list...")
    try:
        apk_parser = ApkParser(apk_path)
        apk_info = apk_parser.parse()
    except Exception as e:
        logger.error(f"Failed to parse APK container: {e}")
        warnings_errors.append(f"APK parsing error: {e}")
        status = "PARTIAL_ANALYSIS"
        apk_info = None

    # 2. Extract and parse all DEX files
    logger.info("[2/7] Disassembling and cross-referencing all DEX files (Multi-DEX)...")
    methods = []
    dex_files_analyzed = []
    try:
        dex_analyzer = MultiDexAnalyzer(apk_path)
        methods = dex_analyzer.extract_and_parse()
        dex_files_analyzed = dex_analyzer.dex_files
        logger.info(f"Analyzed {len(dex_files_analyzed)} DEX files, extracted {len(methods)} method definitions.")
    except Exception as e:
        logger.error(f"Error reading DEX bytecode: {e}")
        warnings_errors.append(f"DEX parsing error: {e}")
        status = "PARTIAL_ANALYSIS"

    # 3. Detect Billing & Payment SDKs
    logger.info("[3/7] Scanning for Google Play Billing, RevenueCat, Stripe, PayPal...")
    billing_detector = BillingDetector(methods)
    billing_findings = billing_detector.detect()

    # 4. Locate Purchase Boolean Methods
    logger.info("[4/7] Running PurchaseBooleanDetector across all DEX methods...")
    boolean_detector = PurchaseBooleanDetector(methods)
    boolean_candidates = boolean_detector.detect()

    # 5. Analyze Constructors (<init>)
    logger.info("[5/7] Analyzing <init> constructors for entitlement setup vs verification...")
    constructor_analyzer = ConstructorAnalyzer(methods)
    constructor_findings = constructor_analyzer.detect()

    # 6. Analyze Network Endpoints
    logger.info("[6/7] Extracting URLs, domains, and payment endpoints...")
    network_analyzer = NetworkAnalyzer(methods)
    network_endpoints = network_analyzer.detect()

    # 7. Classify Architecture (SERVER_SIDE / CLIENT_SIDE / MIXED / UNKNOWN)
    classifier = PaymentArchitectureClassifier(
        billing=billing_findings,
        boolean_candidates=boolean_candidates,
        endpoints=network_endpoints,
        constructors=constructor_findings
    )
    classification_result = classifier.classify()

    # 8. Build Call Graph
    callgraph_builder = PaymentCallGraphBuilder(
        methods=methods,
        boolean_candidates=boolean_candidates,
        network_endpoints=network_endpoints
    )
    call_graph_data = callgraph_builder.build()

    # Compile Overall Evidence
    evidence_list = []
    evidence_list.extend(billing_findings.evidence)
    for c in boolean_candidates[:5]:
        evidence_list.extend(c.purchase_relevance_evidence)
    for ctor in constructor_findings[:5]:
        evidence_list.extend(ctor.evidence)

    from dataclasses import asdict

    apk_dict = asdict(apk_info) if apk_info else {"file_name": os.path.basename(apk_path)}

    report = AnalysisReport(
        apk=apk_dict,
        dex_files=[{"name": d} for d in dex_files_analyzed],
        billing=asdict(billing_findings),
        purchase_boolean_methods=[asdict(c) for c in boolean_candidates],
        constructors=[asdict(c) for c in constructor_findings],
        network={"endpoints": [asdict(e) for e in network_endpoints]},
        call_graph=asdict(call_graph_data),
        classification=asdict(classification_result),
        evidence=list(set(evidence_list)),
        analysis_status=status,
        warnings_or_errors=warnings_errors,
        gemini_interpretation=None,
    )

    # 9. Optional Gemini AI Interpretation
    if enable_gemini:
        logger.info("[AI] Running grounded Gemini AI interpretation on static analysis facts...")
        interpreter = GeminiInterpreter(api_key=gemini_api_key)
        gemini_result = interpreter.interpret(report.to_dict())
        if gemini_result:
            report.gemini_interpretation = asdict(gemini_result)

    # 10. Generate Output Artifacts
    json_path = os.path.join(output_dir, "analysis.json")
    html_path = os.path.join(output_dir, "report.html")

    JsonReporter.generate(report, json_path)
    HtmlReporter.generate(report, html_path)

    logger.info(f"Successfully generated analysis.json at: {json_path}")
    logger.info(f"Successfully generated report.html at: {html_path}")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="APK-Static-Analyzer: Advanced Android Static Analysis & In-App Billing Locator"
    )
    parser.add_argument("--apk", required=True, help="Path to the APK file to analyze")
    parser.add_argument("--output-dir", default="output", help="Directory to save analysis.json and report.html")
    parser.add_argument("--gemini", action="store_true", help="Enable Gemini AI interpretation stage")
    parser.add_argument("--gemini-api-key", default=None, help="Gemini API Key (or use GEMINI_API_KEY env var)")
    parser.add_argument("--jadx-path", default=None, help="Path to JADX executable if available")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not os.path.exists(args.apk):
        logger.error(f"Error: Target APK file does not exist: {args.apk}")
        sys.exit(1)

    try:
        report = run_pipeline(
            apk_path=args.apk,
            output_dir=args.output_dir,
            enable_gemini=args.gemini,
            gemini_api_key=args.gemini_api_key,
            jadx_path=args.jadx_path,
        )

        print("\n==================================================")
        print("           ANALYSIS EXECUTION SUMMARY             ")
        print("==================================================")
        print(f"Package Name: {report.apk.get('package_name')}")
        print(f"Multi-DEX Count: {len(report.dex_files)}")
        print(f"Payment Providers: {', '.join(report.billing.get('providers_detected', [])) or 'None'}")
        print(f"Architecture: {report.classification.get('classification')} (Confidence: {report.classification.get('confidence')})")
        print(f"Boolean Purchase Candidates: {len(report.purchase_boolean_methods)}")
        if report.purchase_boolean_methods:
            top = report.purchase_boolean_methods[0]
            print(f"\n🎯 PRIMARY CANDIDATE (Where is the Boolean purchase check located?):")
            print(f"   DEX:       {top.get('dex_file')}")
            print(f"   Class:     {top.get('class_name')}")
            print(f"   Method:    {top.get('method_name')}{top.get('signature')}")
            print(f"   Return:    {top.get('return_type')}")
            print(f"   Status:    {top.get('status')}")
            print(f"   Location:  {top.get('source_location')}")
        print("==================================================")

    except Exception as e:
        logger.exception(f"Fatal error during analysis: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
