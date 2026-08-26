"""Obfuscation Detector: Evaluates class, method, package name entropy, ProGuard/R8 patterns, and debug info."""
import re
from typing import List, Set, Dict, Any
from analyzer.models import DexMethod, ObfuscationAnalysis, ObfuscationStatus, Confidence
from analyzer.detectors.base import BaseDetector


class ObfuscationDetector(BaseDetector):
    """Detects ProGuard, R8, DexGuard, and custom identifier renaming obfuscation."""

    PROGUARD_SOURCE_FILES = {"SourceFile", "ProGuard", "PG", "R8"}
    
    # Common system/framework packages to exclude from obfuscation ratio calculation
    FRAMEWORK_PREFIXES = (
        "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
        "com.google.android.", "com.android."
    )

    def detect(self) -> ObfuscationAnalysis:
        if not self.methods:
            return ObfuscationAnalysis(
                status=ObfuscationStatus.NO,
                confidence=Confidence.LOW,
                evidence=["No methods available for obfuscation analysis"]
            )

        app_methods = [
            m for m in self.methods
            if not m.class_name.startswith(self.FRAMEWORK_PREFIXES)
        ]
        
        # If all methods filtered out, use all methods
        methods_to_analyze = app_methods if len(app_methods) >= 5 else self.methods

        unique_classes: Set[str] = {m.class_name for m in methods_to_analyze}
        unique_packages: Set[str] = {m.package for m in methods_to_analyze if m.package}

        # 1. Short Class Names (e.g. simple name <= 2 chars like 'a', 'b', 'a$a')
        short_class_count = 0
        for c in unique_classes:
            simple_name = c.split(".")[-1].split("$")[0]
            if len(simple_name) <= 2 and simple_name.isalpha():
                short_class_count += 1

        short_class_ratio = short_class_count / max(1, len(unique_classes))

        # 2. Short Method Names (e.g. name <= 2 chars, ignoring constructors)
        non_special_methods = [m for m in methods_to_analyze if not m.is_constructor]
        short_method_count = 0
        for m in non_special_methods:
            if len(m.method_name) <= 2 and m.method_name.isalpha():
                short_method_count += 1

        short_method_ratio = short_method_count / max(1, len(non_special_methods))

        # 3. Short Package Names (e.g. 'a', 'a.b', 'o.a', 'p000a')
        short_pkg_count = 0
        for p in unique_packages:
            parts = p.split(".")
            if any(len(part) <= 2 or re.match(r"^p\d{3}", part) for part in parts):
                short_pkg_count += 1

        short_package_ratio = short_pkg_count / max(1, len(unique_packages))

        # 4. ProGuard / R8 Patterns & Stripped Source Files
        r8_patterns = set()
        source_file_stripped_count = 0
        total_with_source = 0

        for m in methods_to_analyze:
            if m.source_file is not None:
                total_with_source += 1
                if m.source_file in self.PROGUARD_SOURCE_FILES or m.source_file == "":
                    source_file_stripped_count += 1
            if "$r8$lambda" in m.method_name or "$$InternalSynthetic" in m.class_name:
                r8_patterns.add("R8 synthetic lambda markers ($r8$lambda)")

        missing_debug_ratio = (
            source_file_stripped_count / max(1, total_with_source)
            if total_with_source > 0
            else 1.0
        )

        evidence: List[str] = []

        if short_class_ratio > 0.35:
            evidence.append(f"High percentage of single/double-letter class names ({round(short_class_ratio * 100, 1)}%)")
        if short_method_ratio > 0.30:
            evidence.append(f"High percentage of renamed 1-2 character method names ({round(short_method_ratio * 100, 1)}%)")
        if short_package_ratio > 0.40:
            evidence.append(f"Short / collapsed package hierarchy observed ({round(short_package_ratio * 100, 1)}%)")
        if missing_debug_ratio > 0.50:
            evidence.append(f"SourceFile attribute replaced or stripped ({round(missing_debug_ratio * 100, 1)}% instances)")
        for pat in r8_patterns:
            evidence.append(f"Detected compiler shrinker artifact: {pat}")

        # Classification decision
        score = 0
        if short_class_ratio > 0.40:
            score += 3
        elif short_class_ratio > 0.20:
            score += 1.5

        if short_method_ratio > 0.35:
            score += 3
        elif short_method_ratio > 0.15:
            score += 1.5

        if short_package_ratio > 0.50:
            score += 2
        elif short_package_ratio > 0.25:
            score += 1

        if missing_debug_ratio > 0.60:
            score += 2

        if r8_patterns:
            score += 2

        if score >= 6.0:
            status = ObfuscationStatus.YES
            confidence = Confidence.HIGH
        elif score >= 3.0:
            status = ObfuscationStatus.POSSIBLE
            confidence = Confidence.MEDIUM
        else:
            status = ObfuscationStatus.NO
            confidence = Confidence.HIGH if len(methods_to_analyze) > 20 else Confidence.MEDIUM
            if not evidence:
                evidence.append("Standard readable class, package, and method identifiers preserved")

        return ObfuscationAnalysis(
            status=status,
            confidence=confidence,
            evidence=evidence,
            short_class_ratio=round(short_class_ratio, 3),
            short_method_ratio=round(short_method_ratio, 3),
            short_package_ratio=round(short_package_ratio, 3),
            missing_debug_info_ratio=round(missing_debug_ratio, 3),
            proguard_r8_patterns=sorted(list(r8_patterns)),
        )
