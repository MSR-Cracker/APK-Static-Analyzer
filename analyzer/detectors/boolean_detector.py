"""Boolean Method Detector.

Finds boolean-returning methods that are likely to represent:
    - purchase state
    - subscription state
    - entitlement state
    - premium/pro/vip gates
    - license state
    - access-control gates

The detector is intentionally heuristic. It ranks candidates instead of
claiming that a boolean method is definitely the purchase function.
"""

from typing import List, Dict, Set, Tuple

from analyzer.models import (
    DexMethod,
    BooleanMethodCandidate,
    Confidence,
    StatusState,
)

from analyzer.detectors.base import BaseDetector


class BooleanMethodDetector(BaseDetector):
    """Ranks boolean methods using semantic and bytecode evidence."""

    # ------------------------------------------------------------------
    # Method-name signals
    # ------------------------------------------------------------------

    PREMIUM_METHOD_KEYWORDS: Dict[str, float] = {
        "ispremium": 5.0,
        "ispro": 5.0,
        "isvip": 5.0,
        "issubscribed": 5.5,
        "subscribed": 4.5,

        "haspurchased": 5.5,
        "ispurchased": 6.0,
        "purchase": 4.0,

        "isunlocked": 4.5,
        "haspremium": 5.0,

        "haslicense": 4.5,
        "islicensed": 4.5,
        "isvalidlicense": 5.5,
        "checklicense": 4.0,

        "checkpremium": 4.5,
        "checkpurchase": 5.0,
        "checksubscription": 5.0,

        "isadfree": 4.0,

        "hasactiveentitlement": 6.0,
        "isentitled": 5.5,
        "is_entitled": 5.0,

        "isactive": 2.0,
        "isvalid": 2.0,

        "canaccess": 3.5,
        "hasaccess": 3.5,

        "isfeatureenabled": 2.5,
        "isfeaturesupported": 1.5,

        "getispremium": 4.0,
        "getispro": 4.0,
    }

    # ------------------------------------------------------------------
    # Billing / purchase API signals
    # ------------------------------------------------------------------

    BILLING_SDK_CALLEES: Dict[str, float] = {
        "billingclient": 4.0,
        "querypurchases": 4.5,
        "querypurchasesasync": 5.0,
        "queryproductdetails": 3.0,
        "queryproductdetailsasync": 3.5,
        "getpurchases": 4.0,
        "purchasehistory": 4.0,
        "purchasestate": 4.5,
        "getpurchasestate": 5.0,

        "customerinfo": 4.0,
        "activeentitlements": 5.0,
        "hasactiveentitlement": 5.5,

        "iinappbillingservice": 5.0,
        "inappbilling": 4.0,

        "getsku": 2.5,
        "sku": 2.0,
        "productdetails": 2.0,

        "acknowledgepurchase": 2.5,
        "consumeasync": 3.0,
        "consume": 2.5,
    }

    # ------------------------------------------------------------------
    # Local state signals
    # ------------------------------------------------------------------

    LOCAL_STORAGE_CALLEES: Dict[str, float] = {
        "sharedpreferences": 2.5,
        "getboolean": 2.5,
        "setboolean": 1.5,

        "preferences": 1.5,
        "datastore": 2.0,

        "room": 1.5,
        "sqlite": 1.5,

        "getstring": 0.8,
        "putstring": 0.8,

        "getint": 0.8,
        "putint": 0.8,
    }

    # ------------------------------------------------------------------
    # Class-name signals
    # ------------------------------------------------------------------

    MONETIZATION_CLASS_KEYWORDS: Dict[str, float] = {
        "premium": 3.0,
        "billing": 4.0,
        "purchase": 4.0,
        "subscription": 4.0,
        "entitlement": 4.5,
        "license": 3.5,
        "paywall": 4.0,
        "payment": 3.5,
        "checkout": 3.0,
        "receipt": 3.0,
        "iap": 3.0,
        "inapp": 3.0,
        "transaction": 3.0,
    }

    USER_STATE_CLASS_KEYWORDS: Tuple[str, ...] = (
        "user",
        "account",
        "profile",
        "auth",
        "session",
        "config",
        "state",
        "manager",
        "repository",
        "store",
    )

    # ------------------------------------------------------------------
    # Field / string signals
    # ------------------------------------------------------------------

    PURCHASE_FIELD_KEYWORDS: Tuple[str, ...] = (
        "premium",
        "pro",
        "vip",
        "purchased",
        "purchase",
        "subscribed",
        "subscription",
        "entitlement",
        "license",
        "billing",
        "payment",
        "receipt",
        "sku",
        "productid",
        "product_id",
        "orderid",
        "order_id",
        "transaction",
    )

    PURCHASE_STRING_KEYWORDS: Tuple[str, ...] = (
        "is_premium",
        "ispremium",
        "is_pro",
        "ispro",
        "premium_user",
        "premiumuser",
        "purchased",
        "purchase_state",
        "purchase_state",
        "subscription_id",
        "subscriptionid",
        "sku",
        "product_id",
        "productid",
        "order_id",
        "orderid",
        "entitlement",
        "license",
        "billing",
        "receipt",
        "transaction",
    )

    # ------------------------------------------------------------------
    # Bytecode signals
    # ------------------------------------------------------------------

    CONDITIONAL_OPCODES = {
        "if-eq",
        "if-ne",
        "if-lt",
        "if-ge",
        "if-gt",
        "if-le",
        "if-eqz",
        "if-nez",
        "if-ltz",
        "if-gez",
        "if-gtz",
        "if-lez",
    }

    RETURN_OPCODES = {
        "return",
        "return-object",
        "return-wide",
        "return-void",
    }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _contains_any(
        value: str,
        keywords,
    ) -> List[str]:
        """Return matching keywords without duplicates."""

        text = (
            value or ""
        ).lower()

        found: List[str] = []

        for keyword in keywords:
            if keyword.lower() in text:
                found.append(
                    keyword
                )

        return list(
            dict.fromkeys(
                found
            )
        )

    @staticmethod
    def _add_evidence(
        evidence: List[str],
        text: str,
    ):
        """Append one evidence line only once."""

        if text and text not in evidence:
            evidence.append(text)

    # ------------------------------------------------------------------
    # Method-name scoring
    # ------------------------------------------------------------------

    def _score_method_name(
        self,
        method: DexMethod,
        evidence: List[str],
    ) -> float:
        name = (
            method.method_name or ""
        ).lower()

        if not name:
            return 0.0

        score = 0.0

        # Exact-ish normalized name first.
        for keyword, weight in (
            self.PREMIUM_METHOD_KEYWORDS.items()
        ):
            keyword_lower = (
                keyword.lower()
            )

            if keyword_lower in name:
                score += weight

                self._add_evidence(
                    evidence,
                    (
                        "Method name matches purchase/"
                        f"entitlement pattern "
                        f"'{keyword}' (+{weight:.1f})"
                    ),
                )

                # Prevent one method name from collecting many overlapping
                # points from e.g. "getispro".
                break

        # Boolean methods commonly start with "is"/"has"/"can".
        if name.startswith(
            (
                "is",
                "has",
                "can",
                "should",
                "check",
            )
        ):
            score += 0.5

        return score

    # ------------------------------------------------------------------
    # Class scoring
    # ------------------------------------------------------------------

    def _score_class_name(
        self,
        method: DexMethod,
        evidence: List[str],
    ) -> float:
        class_name = (
            method.class_name or ""
        )

        if not class_name:
            return 0.0

        class_lower = class_name.lower()

        for keyword, weight in (
            self.MONETIZATION_CLASS_KEYWORDS.items()
        ):
            if keyword in class_lower:
                self._add_evidence(
                    evidence,
                    (
                        f"Enclosing class '{class_name}' "
                        "is associated with monetization/"
                        f"entitlement logic "
                        f"(+{weight:.1f})"
                    ),
                )

                return weight

        if any(
            keyword in class_lower
            for keyword
            in self.USER_STATE_CLASS_KEYWORDS
        ):
            self._add_evidence(
                evidence,
                (
                    f"Enclosing class '{class_name}' "
                    "looks like an application/user "
                    "state container (+1.0)"
                ),
            )

            return 1.0

        return 0.0

    # ------------------------------------------------------------------
    # Callee scoring
    # ------------------------------------------------------------------

    def _score_callees(
        self,
        method: DexMethod,
        evidence: List[str],
    ) -> float:
        score = 0.0

        seen_billing: Set[str] = set()
        seen_storage: Set[str] = set()

        for callee in (
            method.callees or []
        ):
            callee_lower = (
                callee.lower()
            )

            # Billing / purchase APIs.
            for keyword, weight in (
                self.BILLING_SDK_CALLEES.items()
            ):
                if keyword in callee_lower:
                    normalized_key = (
                        f"billing:{keyword}"
                    )

                    if normalized_key in seen_billing:
                        break

                    seen_billing.add(
                        normalized_key
                    )

                    score += weight

                    self._add_evidence(
                        evidence,
                        (
                            "Calls billing/purchase API "
                            f"'{callee}' "
                            f"(+{weight:.1f})"
                        ),
                    )

                    break

            # Local state.
            for keyword, weight in (
                self.LOCAL_STORAGE_CALLEES.items()
            ):
                if keyword in callee_lower:
                    normalized_key = (
                        f"storage:{keyword}"
                    )

                    if normalized_key in seen_storage:
                        break

                    seen_storage.add(
                        normalized_key
                    )

                    score += weight

                    self._add_evidence(
                        evidence,
                        (
                            "Reads/writes local state via "
                            f"'{callee}' "
                            f"(+{weight:.1f})"
                        ),
                    )

                    break

        return score

    # ------------------------------------------------------------------
    # Field scoring
    # ------------------------------------------------------------------

    def _score_fields(
        self,
        method: DexMethod,
        evidence: List[str],
    ) -> float:
        score = 0.0

        matched_fields: Set[str] = set()

        for field in (
            method.fields_referenced or []
        ):
            field_lower = (
                field.lower()
            )

            for keyword in (
                self.PURCHASE_FIELD_KEYWORDS
            ):
                if keyword in field_lower:
                    if field_lower in matched_fields:
                        break

                    matched_fields.add(
                        field_lower
                    )

                    score += 2.5

                    self._add_evidence(
                        evidence,
                        (
                            "Accesses purchase/entitlement "
                            f"state field '{field}' "
                            "(+2.5)"
                        ),
                    )

                    break

        return score

    # ------------------------------------------------------------------
    # String scoring
    # ------------------------------------------------------------------

    def _score_strings(
        self,
        method: DexMethod,
        evidence: List[str],
    ) -> float:
        score = 0.0

        matched_strings: Set[str] = set()

        for value in (
            method.strings_referenced or []
        ):
            value_lower = (
                value.lower()
            )

            for keyword in (
                self.PURCHASE_STRING_KEYWORDS
            ):
                if keyword in value_lower:
                    if value in matched_strings:
                        break

                    matched_strings.add(
                        value
                    )

                    score += 2.0

                    self._add_evidence(
                        evidence,
                        (
                            "References monetization "
                            f"string '{value}' "
                            "(+2.0)"
                        ),
                    )

                    break

        return score

    # ------------------------------------------------------------------
    # Caller scoring
    # ------------------------------------------------------------------

    def _score_callers(
        self,
        method: DexMethod,
        evidence: List[str],
    ) -> float:
        callers = (
            method.callers or []
        )

        if not callers:
            return 0.0

        score = min(
            len(callers) * 0.35,
            2.5,
        )

        ui_keywords = (
            "activity",
            "fragment",
            "view",
            "dialog",
            "screen",
            "ui",
            "main",
            "adapter",
            "compose",
        )

        ui_callers = [
            caller
            for caller in callers
            if any(
                keyword in caller.lower()
                for keyword in ui_keywords
            )
        ]

        if ui_callers:
            score += 2.0

            preview = ui_callers[:3]

            self._add_evidence(
                evidence,
                (
                    "Called by likely UI code "
                    f"({preview}) (+2.0)"
                ),
            )

        elif len(callers) >= 3:
            self._add_evidence(
                evidence,
                (
                    f"Referenced by {len(callers)} "
                    "other methods, suggesting a "
                    "reused application-state gate."
                ),
            )

        return score

    # ------------------------------------------------------------------
    # Bytecode scoring
    # ------------------------------------------------------------------

    def _score_bytecode(
        self,
        method: DexMethod,
        evidence: List[str],
    ) -> float:
        score = 0.0

        instructions = (
            method.instructions or []
        )

        branches = (
            method.branches or []
        )

        returns = (
            method.returns or []
        )

        # --------------------------------------------------------------
        # Conditional branches
        # --------------------------------------------------------------

        branch_count = 0

        for branch in branches:
            opcode = str(
                branch.get(
                    "opcode",
                    "",
                )
            ).lower()

            if (
                opcode in self.CONDITIONAL_OPCODES
            ):
                branch_count += 1

        if branch_count:
            score += min(
                branch_count * 0.75,
                2.5,
            )

            self._add_evidence(
                evidence,
                (
                    f"Boolean control flow contains "
                    f"{branch_count} conditional branch(es)"
                ),
            )

        # --------------------------------------------------------------
        # Return behavior
        # --------------------------------------------------------------

        return_count = 0
        constant_boolean_return = False
        constant_values: Set[str] = set()

        for instruction in instructions:
            opcode = (
                instruction.opcode_name
                or ""
            ).lower()

            if opcode in self.RETURN_OPCODES:
                return_count += 1

            if opcode in (
                "const/4",
                "const/16",
                "const",
            ):
                operands = (
                    instruction.operands
                    or ""
                )

                if (
                    "#0" in operands
                    or "#1" in operands
                ):
                    constant_boolean_return = True

                    if "#0" in operands:
                        constant_values.add(
                            "0"
                        )

                    if "#1" in operands:
                        constant_values.add(
                            "1"
                        )

        if constant_boolean_return:
            # Weak evidence only. A method that always returns true/false is
            # not automatically a purchase method.
            score += 0.5

            self._add_evidence(
                evidence,
                (
                    "Bytecode contains boolean-like "
                    "constant assignment "
                    f"(values: {sorted(constant_values)})"
                ),
            )

        if return_count > 1:
            score += 0.5

            self._add_evidence(
                evidence,
                (
                    f"Method has {return_count} return "
                    "path(s), consistent with a state gate"
                ),
            )

        # --------------------------------------------------------------
        # Return instructions plus branches is stronger than either alone.
        # --------------------------------------------------------------

        if branch_count > 0 and return_count >= 2:
            score += 1.5

            self._add_evidence(
                evidence,
                (
                    "Multiple return paths are controlled "
                    "by conditional bytecode"
                ),
            )

        return score

    # ------------------------------------------------------------------
    # Obfuscation / compact identifier scoring
    # ------------------------------------------------------------------

    def _score_obfuscation(
        self,
        method: DexMethod,
        current_score: float,
        evidence: List[str],
    ) -> float:
        name = (
            method.method_name or ""
        )

        if len(name) > 2:
            return 0.0

        callers_count = len(
            method.callers or []
        )

        callees_count = len(
            method.callees or []
        )

        # A one/two-character boolean method becomes interesting when there
        # is independent evidence around it.
        if (
            callers_count >= 2
            and current_score >= 2.0
        ):
            bonus = 1.5

            self._add_evidence(
                evidence,
                (
                    f"Short/obfuscated method identifier "
                    f"'{name}' has {callers_count} caller(s) "
                    f"and independent purchase evidence "
                    f"(+{bonus:.1f})"
                ),
            )

            return bonus

        if (
            callees_count >= 2
            and current_score >= 3.0
        ):
            bonus = 0.75

            self._add_evidence(
                evidence,
                (
                    f"Short/obfuscated method identifier "
                    f"'{name}' has {callees_count} callees "
                    f"and supporting semantic evidence "
                    f"(+{bonus:.1f})"
                ),
            )

            return bonus

        return 0.0

    # ------------------------------------------------------------------
    # Final confidence mapping
    # ------------------------------------------------------------------

    def _confidence_for_score(
        self,
        score: float,
        evidence: List[str],
        method: DexMethod,
    ) -> Tuple[
        Confidence,
        StatusState,
    ]:
        """
        Convert score into a confidence state.

        The score thresholds are intentionally conservative.
        """

        # Strong direct semantic evidence.
        strong_semantic = any(
            text.startswith(
                (
                    "Method name matches "
                    "purchase/entitlement pattern",
                    "Calls billing/purchase API",
                    "Accesses purchase/entitlement state field",
                )
            )
            for text in evidence
        )

        has_control_flow = bool(
            method.branches
        ) and len(
            method.returns or []
        ) >= 1

        if score >= 10.0:
            return (
                Confidence.HIGH,
                StatusState.STRONG_CANDIDATE,
            )

        if score >= 7.0 and (
            strong_semantic
            or has_control_flow
        ):
            return (
                Confidence.HIGH,
                StatusState.STRONG_CANDIDATE,
            )

        if score >= 5.0:
            return (
                Confidence.MEDIUM,
                StatusState.STRONG_CANDIDATE,
            )

        return (
            Confidence.LOW,
            StatusState.POSSIBLE,
        )

    # ------------------------------------------------------------------
    # Main detector
    # ------------------------------------------------------------------

    def detect(
        self,
    ) -> List[BooleanMethodCandidate]:
        candidates: List[
            BooleanMethodCandidate
        ] = []

        for method in self.methods:
            # ----------------------------------------------------------
            # Only boolean-returning methods are eligible.
            # ----------------------------------------------------------

            return_type = (
                method.return_type or ""
            )

            signature = (
                method.signature or ""
            )

            is_bool_return = (
                return_type == "boolean"
                or return_type == "Z"
                or signature.endswith(")Z")
            )

            if not is_bool_return:
                continue

            score = 0.0

            evidence: List[str] = []

            # ----------------------------------------------------------
            # Independent evidence channels.
            # ----------------------------------------------------------

            score += self._score_method_name(
                method,
                evidence,
            )

            score += self._score_class_name(
                method,
                evidence,
            )

            score += self._score_callees(
                method,
                evidence,
            )

            score += self._score_fields(
                method,
                evidence,
            )

            score += self._score_strings(
                method,
                evidence,
            )

            score += self._score_callers(
                method,
                evidence,
            )

            score += self._score_bytecode(
                method,
                evidence,
            )

            # Obfuscation bonus must come after collecting independent
            # evidence; otherwise every short method would rank highly.
            score += self._score_obfuscation(
                method,
                score,
                evidence,
            )

            # ----------------------------------------------------------
            # Network evidence.
            #
            # A URL alone is not enough. It becomes useful when the same
            # method already has purchase/billing semantics.
            # ----------------------------------------------------------

            network_strings = [
                value
                for value in (
                    method.strings_referenced
                    or []
                )
                if value.startswith(
                    (
                        "http://",
                        "https://",
                    )
                )
            ]

            if network_strings:
                network_purchase_hits = self._contains_any(
                    " ".join(
                        network_strings
                    ),
                    (
                        "verify",
                        "validate",
                        "purchase",
                        "subscription",
                        "receipt",
                        "entitlement",
                        "license",
                        "billing",
                        "payment",
                        "order",
                    ),
                )

                if network_purchase_hits:
                    score += 2.5

                    self._add_evidence(
                        evidence,
                        (
                            "References network endpoint(s) "
                            "whose path/name suggests purchase "
                            f"verification: "
                            f"{network_purchase_hits[:4]} "
                            "(+2.5)"
                        ),
                    )

            # ----------------------------------------------------------
            # Minimum threshold.
            # ----------------------------------------------------------

            if score < 2.5:
                continue

            confidence, status = (
                self._confidence_for_score(
                    score,
                    evidence,
                    method,
                )
            )

            # Prefer a concise explanation while retaining complete
            # evidence in purchase_relevance_evidence.
            why = (
                "; ".join(
                    evidence[:4]
                )
                if evidence
                else (
                    "Boolean method matches "
                    "purchase/entitlement gate heuristics"
                )
            )

            snippet = (
                method.bytecode_snippet
                or method.decompiled_source
            )

            candidate = BooleanMethodCandidate(
                dex_file=method.dex_file,
                class_name=method.class_name,
                package=method.package,
                method_name=method.method_name,
                signature=method.signature,
                return_type=method.return_type,
                source_apk=method.source_apk,
                parameters=method.parameters,
                access_flags=method.access_flags,
                is_static=method.is_static,
                is_native=method.is_native,
                is_abstract=method.is_abstract,
                is_constructor=method.is_constructor,
                source_location=(
                    f"{method.class_name}"
                    f"->{method.method_name}"
                ),
                callers=method.callers,
                callees=method.callees,
                confidence=confidence,
                status=status,
                purchase_relevance_evidence=evidence,
                score=round(
                    score,
                    1,
                ),
                decompiled_snippet=snippet,
                why_identified=why,
                analysis_quality=method.analysis_quality,
            )

            candidates.append(
                candidate
            )

        # --------------------------------------------------------------
        # Stable ranking
        # --------------------------------------------------------------

        confidence_rank = {
            Confidence.HIGH: 0,
            Confidence.MEDIUM: 1,
            Confidence.LOW: 2,
        }

        candidates.sort(
            key=lambda candidate: (
                -candidate.score,
                confidence_rank.get(
                    candidate.confidence,
                    9,
                ),
                candidate.class_name.lower(),
                candidate.method_name.lower(),
                candidate.dex_file.lower(),
            )
        )

        return candidates
