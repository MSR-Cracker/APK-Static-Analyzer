"""JSON Reporter: Exports full structured analysis findings into output/analysis.json."""
import os
import json
import dataclasses
from typing import Any
from analyzer.models import AnalysisReport


class EnhancedJSONEncoder(json.JSONEncoder):
    """Custom encoder handling dataclasses and Enums."""
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if hasattr(o, "value"):
            return o.value
        if isinstance(o, set):
            return list(o)
        return super().default(o)


class JsonReporter:
    """Serializes the AnalysisReport model to a cleanly formatted JSON file."""

    def __init__(self, report: AnalysisReport, output_path: str = "output/analysis.json"):
        self.report = report
        self.output_path = output_path

    def generate(self) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(self.output_path)), exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, cls=EnhancedJSONEncoder, indent=2, ensure_ascii=False)
        return self.output_path
