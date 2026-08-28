"""Class-Level Analyzer.

Ranks purchase/billing/entitlement classes and selects the most relevant
boolean entitlement gate.

Selection is based on correlated static evidence rather than class names
alone.
"""

from collections import defaultdict
from typing import List, Dict, Set, Optional, Tuple, Any

from analyzer.models import (
    DexMethod,
    BillingFinding,
    BooleanMethodCandidate,
    ConstructorFinding,
    ClassLevelAnalysis,
    Confidence,
    StatusState,
)


class ClassLevelAnalyzer:
    """Ranks and selects primary purchase/entitlement analysis targets."""

    MONETIZATION_KEYWORDS = (
        "billing",
        "purchase",
        "subscription",
        "entitlement",
        "premium",
        "paywall",
        "payment",
        "checkout",
        "receipt",
        "transaction",
        "license",
        "iap",
        "inapp",
    )

    PREMIUM_KEYWORDS = (
        "premium",
        "pro",
        "vip",
        "entitlement",
        "subscription",
        "license",
        "account",
        "user",
        "profile",
        "paywall",
    )

    BILLING_METHOD_KEYWORDS = (
        "billing",
        "purchase",
        "subscription",
        "entitlement",
        "receipt",
        "payment",
        "checkout",
        "transaction",
        "license",
        "querypurchases",
        "queryproductdetails",
        "customerinfo",
        "activeentitlements",
    )

    def __init__(
        self,
        methods: List[DexMethod],
        billing: BillingFinding,
        boolean_candidates: List[BooleanMethodCandidate],
        constructors: List[ConstructorFinding],
    ):
        self.methods = methods or []
        self.billing = billing
        self.boolean_candidates = (
            boolean_candidates or []
        )
        self.constructors = (
            constructors or []
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _add_score(
        scores: Dict[str, float],
        class_name: str,
        amount: float,
    ) -> None:
        if not class_name:
            return

        scores[class_name] += amount

    @staticmethod
    def _contains_any(
        value: str,
        keywords,
    ) -> bool:
        text = (
            value or ""
        ).lower()

        return any(
            keyword in text
            for keyword in keywords
        )

    @staticmethod
    def _candidate_status_rank(
        status: StatusState,
    ) -> int:
        if status == StatusState.CONFIRMED:
            return 0

        if status == StatusState.STRONG_CANDIDATE:
            return 1

        if status == StatusState.POSSIBLE:
            return 2

        return 3

    def _candidate_rank_key(
        self,
        candidate: BooleanMethodCandidate,
    ) -> Tuple[Any, ...]:
        """Rank boolean candidates with confirmed call-site gates first."""

        return (
            self._candidate_status_rank(
                candidate.status
            ),
            -float(
                candidate.score
            ),
            -len(
                candidate.callers or []
            ),
            candidate.class_name.lower(),
            candidate.method_name.lower(),
            candidate.dex_file.lower(),
        )

    def _class_has_method(
        self,
        class_name: str,
    ) -> bool:
        return any(
            method.class_name == class_name
            for method in self.methods
        )

    # ------------------------------------------------------------------
    # Billing class scoring
    # ------------------------------------------------------------------

    def _score_billing_classes(
        self,
        scores: Dict[str, float],
        evidence: List[str],
    ) -> None:
        for class_name in (
            self.billing.billing_classes
            or []
        ):
            if not class_name:
                continue

            self._add_score(
                scores,
                class_name,
                3.0,
            )

            if self._contains_any(
                class_name,
                self.MONETIZATION_KEYWORDS,
            ):
                self._add_score(
                    scores,
                    class_name,
                    2.0,
                )

    # ------------------------------------------------------------------
    # Boolean candidate scoring
    # ------------------------------------------------------------------

    def _score_boolean_candidates(
        self,
        purchase_scores: Dict[str, float],
        premium_scores: Dict[str, float],
        evidence: List[str],
    ) -> None:
        for candidate in (
            self.boolean_candidates
        ):
            class_name = (
                candidate.class_name
            )

            if not class_name:
                continue

            score = max(
                0.0,
                float(
                    candidate.score
                ),
            )

            # Primary source of class-level relevance.
            self._add_score(
                purchase_scores,
                class_name,
                score,
            )

            self._add_score(
                premium_scores,
                class_name,
                score * 0.7,
            )

            # Confirmed boolean gate gets a strong class bonus.
            if candidate.status == StatusState.CONFIRMED:
                self._add_score(
                    purchase_scores,
                    class_name,
                    6.0,
                )

                self._add_score(
                    premium_scores,
                    class_name,
                    6.0,
                )

                evidence.append(
                    f"Class '{class_name}' contains a confirmed "
                    f"boolean entitlement gate "
                    f"'{candidate.method_name}'."
                )

            elif candidate.status == StatusState.STRONG_CANDIDATE:
                self._add_score(
                    purchase_scores,
                    class_name,
                    2.0,
                )

                self._add_score(
                    premium_scores,
                    class_name,
                    2.0,
                )

            # Strong semantic class hints.
            if self._contains_any(
                class_name,
                self.PREMIUM_KEYWORDS,
            ):
                self._add_score(
                    premium_scores,
                    class_name,
                    2.5,
                )

            if self._contains_any(
                class_name,
                self.MONETIZATION_KEYWORDS,
            ):
                self._add_score(
                    purchase_scores,
                    class_name,
                    2.5,
                )

            # Cross-reference strength.
            caller_count = len(
                candidate.callers or []
            )

            if caller_count:
                self._add_score(
                    premium_scores,
                    class_name,
                    min(
                        caller_count * 0.35,
                        2.5,
                    ),
                )

    # ------------------------------------------------------------------
    # Constructor scoring
    # ------------------------------------------------------------------

    def _score_constructors(
        self,
        purchase_scores: Dict[str, float],
        premium_scores: Dict[str, float],
        evidence: List[str],
    ) -> None:
        for constructor in (
            self.constructors
        ):
            class_name = (
                constructor.class_name
            )

            if not class_name:
                continue

            if (
                constructor.initializes_billing_client
            ):
                self._add_score(
                    purchase_scores,
                    class_name,
                    3.0,
                )

                evidence.append(
                    f"Constructor '{class_name}-><init>' "
                    "initializes a billing client."
                )

            if constructor.sets_premium_flags:
                self._add_score(
                    premium_scores,
                    class_name,
                    3.0,
                )

            if constructor.reads_local_state:
                self._add_score(
                    premium_scores,
                    class_name,
                    1.5,
                )

            if constructor.loads_remote_config:
                self._add_score(
                    purchase_scores,
                    class_name,
                    1.5,
                )

            if (
                constructor.verification
                == "YES"
            ):
                self._add_score(
                    purchase_scores,
                    class_name,
                    2.5,
                )

                self._add_score(
                    premium_scores,
                    class_name,
                    2.5,
                )

                evidence.append(
                    f"Constructor '{class_name}-><init>' "
                    "contains entitlement/purchase verification evidence."
                )

    # ------------------------------------------------------------------
    # Billing method scoring
    # ------------------------------------------------------------------

    def _score_billing_methods(
        self,
        purchase_scores: Dict[str, float],
        evidence: List[str],
    ) -> None:
        billing_method_names = {
            value.lower()
            for value in (
                self.billing.billing_methods
                or []
            )
        }

        for method_repr in billing_method_names:
            class_name = (
                method_repr.split(
                    "->",
                    1,
                )[0]
                if "->" in method_repr
                else ""
            )

            method_name = (
                method_repr.split(
                    "->",
                    1,
                )[1]
                if "->" in method_repr
                else method_repr
            )

            if not class_name:
                continue

            self._add_score(
                purchase_scores,
                class_name,
                2.0,
            )

            if self._contains_any(
                method_name,
                self.BILLING_METHOD_KEYWORDS,
            ):
                self._add_score(
                    purchase_scores,
                    class_name,
                    1.5,
                )

    # ------------------------------------------------------------------
    # Method-level class discovery
    # ------------------------------------------------------------------

    def _score_method_inventory(
        self,
        purchase_scores: Dict[str, float],
        premium_scores: Dict[str, float],
    ) -> None:
        """Use actual method names as secondary class evidence."""

        per_class_method_hits = defaultdict(int)

        for method in self.methods:
            class_name = (
                method.class_name
            )

            if not class_name:
                continue

            if self._contains_any(
                method.method_name,
                self.BILLING_METHOD_KEYWORDS,
            ):
                per_class_method_hits[
                    class_name
                ] += 1

        for class_name, count in (
            per_class_method_hits.items()
        ):
            self._add_score(
                purchase_scores,
                class_name,
                min(
                    count * 1.0,
                    4.0,
                ),
            )

            if self._contains_any(
                class_name,
                self.PREMIUM_KEYWORDS,
            ):
                self._add_score(
                    premium_scores,
                    class_name,
                )

    # ------------------------------------------------------------------
    # Ranking
    # ------------------------------------------------------------------

    @staticmethod
    def _rank_classes(
        scores: Dict[str, float],
        limit: int = 5,
    ) -> List[str]:
        return [
            class_name
            for class_name, _score in sorted(
                scores.items(),
                key=lambda item: (
                    -item[1],
                    item[0].lower(),
                ),
            )[:limit]
        ]

    def _select_primary_boolean(
        self,
    ) -> Optional[BooleanMethodCandidate]:
        """Select the best boolean candidate.

        Confirmed verification sites always outrank unverified candidates,
        even when the latter has a marginally higher heuristic score.
        """

        if not self.boolean_candidates:
            return None

        ranked = sorted(
            self.boolean_candidates,
            key=self._candidate_rank_key,
        )

        return ranked[0]

    # ------------------------------------------------------------------
    # Confidence
    # ------------------------------------------------------------------

    def _calculate_confidence(
        self,
        primary_purchase: Optional[str],
        primary_premium: Optional[str],
        primary_boolean: Optional[
            BooleanMethodCandidate
        ],
        purchase_scores: Dict[str, float],
        premium_scores: Dict[str, float],
    ) -> Confidence:

        if not primary_boolean:
            return Confidence.LOW

        if (
            primary_boolean.status
            == StatusState.CONFIRMED
        ):
            return Confidence.HIGH

        boolean_score = (
            float(
                primary_boolean.score
            )
        )

        purchase_score = (
            purchase_scores.get(
                primary_purchase or "",
                0.0,
            )
        )

        premium_score = (
            premium_scores.get(
                primary_premium or "",
                0.0,
            )
        )

        if (
            boolean_score >= 7.0
            and max(
                purchase_score,
                premium_score,
            ) >= 8.0
        ):
            return Confidence.HIGH

        if (
            boolean_score >= 4.0
            or max(
                purchase_score,
                premium_score,
            ) >= 5.0
        ):
            return Confidence.MEDIUM

        return Confidence.LOW

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
    ) -> ClassLevelAnalysis:
        evidence: List[str] = []

        purchase_class_scores: Dict[
            str,
            float,
        ] = defaultdict(float)

        premium_class_scores: Dict[
            str,
            float,
        ] = defaultdict(float)

        # --------------------------------------------------------------
        # Score all independent evidence sources.
        # --------------------------------------------------------------

        self._score_billing_classes(
            purchase_class_scores,
            evidence,
        )

        self._score_boolean_candidates(
            purchase_class_scores,
            premium_class_scores,
            evidence,
        )

        self._score_constructors(
            purchase_class_scores,
            premium_class_scores,
            evidence,
        )

        self._score_billing_methods(
            purchase_class_scores,
            evidence,
        )

        self._score_method_inventory(
            purchase_class_scores,
            premium_class_scores,
        )

        # --------------------------------------------------------------
        # Ranked classes.
        # --------------------------------------------------------------

        top_purchase = self._rank_classes(
            purchase_class_scores,
            limit=5,
        )

        top_premium = self._rank_classes(
            premium_class_scores,
            limit=5,
        )

        primary_purchase = (
            top_purchase[0]
            if top_purchase
            else None
        )

        primary_premium = (
            top_premium[0]
            if top_premium
            else primary_purchase
        )

        # --------------------------------------------------------------
        # Primary boolean.
        # --------------------------------------------------------------

        primary_boolean_candidate = (
            self._select_primary_boolean()
        )

        primary_boolean = None
        primary_boolean_dex = None
        primary_boolean_signature = None

        if primary_boolean_candidate:
            primary_boolean = (
                f"{primary_boolean_candidate.class_name}"
                f"->{primary_boolean_candidate.method_name}"
            )

            primary_boolean_dex = (
                primary_boolean_candidate.dex_file
            )

            primary_boolean_signature = (
                primary_boolean_candidate.signature
            )

            evidence.append(
                f"Primary boolean gate selected: "
                f"'{primary_boolean_candidate.class_name}"
                f"->{primary_boolean_candidate.method_name}"
                f"{primary_boolean_candidate.signature}' "
                f"with status "
                f"'{primary_boolean_candidate.status.value}' "
                f"and score "
                f"{primary_boolean_candidate.score}."
            )

        # --------------------------------------------------------------
        # Additional class evidence.
        # --------------------------------------------------------------

        if primary_purchase:
            evidence.append(
                "Primary purchase/billing class: "
                f"'{primary_purchase}'."
            )

        if primary_premium:
            evidence.append(
                "Primary premium/entitlement class: "
                f"'{primary_premium}'."
            )

        confidence = self._calculate_confidence(
            primary_purchase,
            primary_premium,
            primary_boolean_candidate,
            purchase_class_scores,
            premium_class_scores,
        )

        # --------------------------------------------------------------
        # Avoid duplicate evidence entries.
        # --------------------------------------------------------------

        evidence = list(
            dict.fromkeys(
                evidence
            )
        )

        return ClassLevelAnalysis(
            primary_purchase_class=primary_purchase,
            primary_premium_class=primary_premium,
            primary_boolean_method=primary_boolean,
            primary_boolean_dex=primary_boolean_dex,
            primary_boolean_signature=primary_boolean_signature,
            confidence=confidence,
            evidence=evidence,
            top_purchase_classes=top_purchase,
            top_premium_classes=top_premium,
        )
