"""Class-Level Analyzer: Identifies primary purchase manager and primary premium entitlement classes."""
from typing import List, Dict, Set, Optional
from collections import Counter
from analyzer.models import (
    DexMethod, BillingFinding, BooleanMethodCandidate,
    ConstructorFinding, ClassLevelAnalysis, Confidence
)


class ClassLevelAnalyzer:
    """Ranks and selects Primary Purchase Class, Primary Premium Class, and Primary Boolean Method."""

    def __init__(
        self,
        methods: List[DexMethod],
        billing: BillingFinding,
        boolean_candidates: List[BooleanMethodCandidate],
        constructors: List[ConstructorFinding]
    ):
        self.methods = methods
        self.billing = billing
        self.boolean_candidates = boolean_candidates
        self.constructors = constructors

    def analyze(self) -> ClassLevelAnalysis:
        evidence: List[str] = []
        purchase_class_scores: Counter = Counter()
        premium_class_scores: Counter = Counter()

        # 1. Score from Billing Detector classes
        for c in self.billing.billing_classes:
            purchase_class_scores[c] += 3.0
            if "billing" in c.lower() or "purchase" in c.lower():
                purchase_class_scores[c] += 2.0

        # 2. Score from Boolean candidates
        for b in self.boolean_candidates:
            c_name = b.class_name
            score_contribution = b.score
            if "premium" in c_name.lower() or "entitlement" in c_name.lower() or "account" in c_name.lower():
                premium_class_scores[c_name] += score_contribution
            else:
                purchase_class_scores[c_name] += score_contribution
                premium_class_scores[c_name] += score_contribution * 0.7

        # 3. Score from Constructors
        for ctor in self.constructors:
            c_name = ctor.class_name
            if ctor.initializes_billing_client or ctor.sets_premium_flags:
                purchase_class_scores[c_name] += 2.5
            if ctor.verification == "YES":
                premium_class_scores[c_name] += 2.5

        top_purchase = [c for c, _ in purchase_class_scores.most_common(5)]
        top_premium = [c for c, _ in premium_class_scores.most_common(5)]

        primary_purchase = top_purchase[0] if top_purchase else None
        primary_premium = top_premium[0] if top_premium else primary_purchase

        primary_boolean = None
        primary_boolean_dex = None
        primary_boolean_sig = None

        if self.boolean_candidates:
            top_cand = self.boolean_candidates[0]
            primary_boolean = f"{top_cand.class_name}->{top_cand.method_name}"
            primary_boolean_dex = top_cand.dex_file
            primary_boolean_sig = top_cand.signature

        confidence = Confidence.LOW
        if primary_purchase and self.boolean_candidates:
            top_score = self.boolean_candidates[0].score
            if top_score >= 6.0:
                confidence = Confidence.HIGH
            elif top_score >= 3.5:
                confidence = Confidence.MEDIUM

        if primary_purchase:
            evidence.append(f"Identified primary billing coordination class: '{primary_purchase}'")
        if primary_premium and primary_premium != primary_purchase:
            evidence.append(f"Identified primary entitlement model/state class: '{primary_premium}'")
        if primary_boolean:
            evidence.append(f"Identified primary gate boolean check: '{primary_boolean}' ({primary_boolean_dex})")

        return ClassLevelAnalysis(
            primary_purchase_class=primary_purchase,
            primary_premium_class=primary_premium,
            primary_boolean_method=primary_boolean,
            primary_boolean_dex=primary_boolean_dex,
            primary_boolean_signature=primary_boolean_sig,
            confidence=confidence,
            evidence=evidence,
            top_purchase_classes=top_purchase,
            top_premium_classes=top_premium,
        )
