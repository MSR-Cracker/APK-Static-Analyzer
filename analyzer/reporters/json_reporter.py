"""JSON Reporter: Generates structured and schema-compliant analysis.json."""
import json
from typing import Dict, Any
from analyzer.models import AnalysisReport


class JsonReporter:
    """Serializes analysis findings to compliant analysis.json."""

    @staticmethod
    def generate(report: AnalysisReport, output_path: str) -> Dict[str, Any]:
        data = {
            "apk": report.apk,
            "dex_files": report.dex_files,
            "billing": report.billing,
            "purchase_boolean_methods": report.purchase_boolean_methods,
            "constructors": report.constructors,
            "network": report.network,
            "call_graph": report.call_graph,
            "classification": report.classification,
            "evidence": report.evidence,
            "analysis_status": report.analysis_status,
            "warnings_or_errors": report.warnings_or_errors,
        }

        if report.gemini_interpretation:
            data["gemini_interpretation"] = report.gemini_interpretation

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return data
