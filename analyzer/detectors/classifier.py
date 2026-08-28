"""Payment Architecture Classifier.

Classifies entitlement/payment verification architecture into:
SERVER_SIDE, CLIENT_SIDE, MIXED, or UNKNOWN.

The classifier intentionally distinguishes:
- SDK presence
- network endpoint discovery
- actual verification call sites
- local boolean control-flow gates

A URL or billing SDK by itself is not considered proof of server-authoritative
verification.
"""

from typing import List, Optional, Set

from analyzer.models import (
    ClassificationFinding,
    ClassificationType,
    Confidence,
    BillingFinding,
    BooleanMethodCandidate,
    NetworkEndpoint,
    ConstructorFinding,
    BooleanVerificationLocation,
    CallSiteFinding,
    StatusState,
)


class PaymentArchitectureClassifier:
    """Classifies payment verification architecture from correlated evidence."""

    SERVER_KEYWORDS = {
        "verify",
        "validate",
        "receipt",
        "entitlement",
        "subscription",
        "purchase",
        "license",
        "order",
        "checkout",
        "billing",
        "sync",
        "customerinfo",
        "customer_info",
        "activeentitlement",
        "active_entitlement",
    }

    REMOTE_CALLEE_KEYWORDS = {
        "verifyserver",
        "verifyreceipt",
        "validatereceipt",
        "verifyreceipt",
        "checkentitlement",
        "syncsubscription",
        "syncentitlement",
        "apiclient",
        "retrofit",
        "okhttp",
        "httpurlconnection",
        "volley",
        "webview",
        "execute",
        "enqueue",
        "request",
        "post",
        "get",
    }

    LOCAL_STORAGE_KEYWORDS = {
        "sharedpreferences",
        "getboolean",
        "setboolean",
        "preferences",
        "datastore",
        "room",
        "sqlite",
        "localstorage",
        "cache",
        "cached",
        "persist",
        "loadstate",
        "savestate",
    }

    BILLING_CLASS_KEYWORDS = {
        "billing",
        "purchase",
        "subscription",
        "entitlement",
        "premium",
        "paywall",
        "license",
        "pro",
    }

    def __init__(
        self,
        billing: BillingFinding,
        boolean_candidates: List[BooleanMethodCandidate],
        endpoints: List[NetworkEndpoint],
        constructors: List[ConstructorFinding],
        verification_locations: Optional[
            List[BooleanVerificationLocation]
        ] = None,
        call_sites: Optional[
            List[CallSiteFinding]
        ] = None,
    ):
        self.billing = billing
        self.boolean_candidates = (
            boolean_candidates or []
        )
        self.endpoints = (
            endpoints or []
        )
        self.constructors = (
            constructors or []
        )
        self.verification_locations = (
            verification_locations or []
        )
        self.call_sites = (
            call_sites or []
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _contains_keyword(
        value: str,
        keywords: Set[str],
    ) -> bool:
        normalized = (
            value or ""
        ).lower()

        return any(
            keyword in normalized
            for keyword in keywords
        )

    @staticmethod
    def _candidate_key(
        class_name: str,
        method_name: str,
    ) -> str:
        return (
            f"{class_name}->{method_name}"
        ).lower()

    def _is_purchase_related_endpoint(
        self,
        endpoint: NetworkEndpoint,
    ) -> bool:
        """Determine whether an endpoint is semantically payment-related."""

        if endpoint.is_purchase_related:
            return True

        endpoint_text = " ".join(
            [
                endpoint.url or "",
                endpoint.domain or "",
                endpoint.referenced_from_class or "",
                endpoint.referenced_from_method or "",
            ]
        ).lower()

        return self._contains_keyword(
            endpoint_text,
            self.SERVER_KEYWORDS,
        )

    def _is_remote_callee(
        self,
        callee: str,
    ) -> bool:
        return self._contains_keyword(
            callee,
            self.REMOTE_CALLEE_KEYWORDS,
        )

    def _is_local_storage_callee(
        self,
        callee: str,
    ) -> bool:
        return self._contains_keyword(
            callee,
            self.LOCAL_STORAGE_KEYWORDS,
        )

    def _candidate_has_local_evidence(
        self,
        candidate: BooleanMethodCandidate,
    ) -> bool:
        """Check local persistence evidence associated with a boolean gate."""

        for callee in (
            candidate.callees or []
        ):
            if self._is_local_storage_callee(
                callee
            ):
                return True

        for evidence in (
            candidate.purchase_relevance_evidence
            or []
        ):
            evidence_lower = (
                evidence or ""
            ).lower()

            if (
                "sharedpreferences"
                in evidence_lower
                or "local storage"
                in evidence_lower
                or "local device"
                in evidence_lower
                or "preferences"
                in evidence_lower
            ):
                return True

        return False

    # ------------------------------------------------------------------
    # Server-side evidence
    # ------------------------------------------------------------------

    def _collect_server_evidence(
        self,
    ) -> List[str]:
        evidence: List[str] = []

        # --------------------------------------------------------------
        # 1. Correlated remote verification in boolean methods
        # --------------------------------------------------------------

        for candidate in (
            self.boolean_candidates
        ):
            for callee in (
                candidate.callees or []
            ):
                if self._contains_keyword(
                    callee,
                    {
                        "verifyserver",
                        "verifyreceipt",
                        "validatereceipt",
                        "checkentitlement",
                        "syncsubscription",
                        "syncentitlement",
                    },
                ):
                    evidence.append(
                        f"Boolean gate "
                        f"'{candidate.class_name}"
                        f"->{candidate.method_name}' "
                        f"delegates to remote verification "
                        f"routine '{callee}'."
                    )

        # --------------------------------------------------------------
        # 2. Payment-related network endpoints
        #
        # Endpoint existence alone is weak. It becomes meaningful when
        # the endpoint is referenced from a payment/billing/entitlement
        # class or method.
        # --------------------------------------------------------------

        for endpoint in (
            self.endpoints
        ):
            if not self._is_purchase_related_endpoint(
                endpoint
            ):
                continue

            source_text = " ".join(
                [
                    endpoint.referenced_from_class or "",
                    endpoint.referenced_from_method or "",
                ]
            ).lower()

            correlated = (
                self._contains_keyword(
                    source_text,
                    self.BILLING_CLASS_KEYWORDS,
                )
                or endpoint.relevance_level
                == "HIGH"
            )

            if correlated:
                evidence.append(
                    f"Purchase-related network endpoint "
                    f"'{endpoint.url}' is referenced from "
                    f"'{endpoint.referenced_from_class}"
                    f"->{endpoint.referenced_from_method}'."
                )

        # --------------------------------------------------------------
        # 3. Constructor remote verification
        # --------------------------------------------------------------

        for constructor in (
            self.constructors
        ):
            if (
                constructor.verification
                == "YES"
                and constructor.network_interaction
                == "YES"
            ):
                evidence.append(
                    f"Constructor in "
                    f"'{constructor.class_name}' "
                    "performs verified entitlement/purchase "
                    "logic together with network interaction."
                )

        # --------------------------------------------------------------
        # 4. Remote calls from confirmed boolean gates
        # --------------------------------------------------------------

        for candidate in (
            self.boolean_candidates
        ):
            if candidate.status != StatusState.CONFIRMED:
                continue

            remote_callees = [
                callee
                for callee in (
                    candidate.callees or []
                )
                if self._is_remote_callee(
                    callee
                )
            ]

            if remote_callees:
                evidence.append(
                    f"Confirmed boolean gate "
                    f"'{candidate.class_name}"
                    f"->{candidate.method_name}' "
                    "contains remote/network interaction: "
                    + ", ".join(
                        remote_callees[:5]
                    )
                )

        # Remove duplicates while preserving order.
        return list(
            dict.fromkeys(
                evidence
            )
        )

    # ------------------------------------------------------------------
    # Client-side evidence
    # ------------------------------------------------------------------

    def _collect_client_evidence(
        self,
    ) -> List[str]:
        evidence: List[str] = []

        # --------------------------------------------------------------
        # 1. Actual boolean verification call sites
        # --------------------------------------------------------------

        for location in (
            self.verification_locations
        ):
            evidence.append(
                f"Local control-flow gate in "
                f"'{location.class_name}"
                f"->{location.method_name}' "
                f"tests boolean result of "
                f"'{location.called_boolean_class}"
                f"->{location.called_boolean_method}' "
                f"using {location.branch_opcode}."
            )

        # --------------------------------------------------------------
        # 2. Call sites with an actual conditional branch
        # --------------------------------------------------------------

        verified_location_keys = {
            self._candidate_key(
                location.class_name,
                location.method_name,
            )
            for location in (
                self.verification_locations
            )
        }

        for call_site in (
            self.call_sites
        ):
            if not call_site.conditional_branch:
                continue

            caller_key = self._candidate_key(
                call_site.caller_class,
                call_site.caller_method,
            )

            # Avoid duplicating locations already recorded above.
            if caller_key in verified_location_keys:
                continue

            evidence.append(
                f"Boolean result from "
                f"'{call_site.called_class}"
                f"->{call_site.called_method}' "
                f"is consumed by conditional branch "
                f"'{call_site.conditional_branch}' "
                f"in '{call_site.caller_class}"
                f"->{call_site.caller_method}'."
            )

        # --------------------------------------------------------------
        # 3. Confirmed boolean methods using local state
        # --------------------------------------------------------------

        for candidate in (
            self.boolean_candidates
        ):
            if candidate.status not in (
                StatusState.CONFIRMED,
                StatusState.STRONG_CANDIDATE,
            ):
                continue

            if self._candidate_has_local_evidence(
                candidate
            ):
                evidence.append(
                    f"Boolean entitlement method "
                    f"'{candidate.class_name}"
                    f"->{candidate.method_name}' "
                    "uses local device state/preferences."
                )

        # --------------------------------------------------------------
        # 4. Constructors initializing local entitlement state
        # --------------------------------------------------------------

        for constructor in (
            self.constructors
        ):
            if (
                constructor.verification
                == "YES"
                and constructor.reads_local_state
            ):
                evidence.append(
                    f"Constructor in "
                    f"'{constructor.class_name}' "
                    "reads local entitlement/premium state."
                )

        return list(
            dict.fromkeys(
                evidence
            )
        )

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(
        self,
    ) -> ClassificationFinding:
        """Classify architecture using correlated static evidence."""

        server_evidence = (
            self._collect_server_evidence()
        )

        client_evidence = (
            self._collect_client_evidence()
        )

        reasons: List[str] = []

        # ==============================================================
        # Strong evidence paths
        # ==============================================================

        has_server = bool(
            server_evidence
        )

        has_client = bool(
            client_evidence
        )

        if has_server and has_client:
            classification = (
                ClassificationType.MIXED
            )

            # Both independent paths exist. Confidence is HIGH when
            # either side has multiple pieces of evidence.
            if (
                len(server_evidence) >= 2
                or len(client_evidence) >= 2
            ):
                confidence = Confidence.HIGH
            else:
                confidence = Confidence.MEDIUM

            reasons.append(
                "Static evidence shows both remote "
                "verification/network pathways and local "
                "on-device entitlement control-flow gating."
            )

        elif has_server:
            classification = (
                ClassificationType.SERVER_SIDE
            )

            if len(server_evidence) >= 2:
                confidence = Confidence.HIGH
            else:
                confidence = Confidence.MEDIUM

            reasons.append(
                "Remote payment/entitlement verification "
                "evidence was identified without a separately "
                "confirmed local boolean gate."
            )

        elif has_client:
            classification = (
                ClassificationType.CLIENT_SIDE
            )

            if (
                self.verification_locations
                and len(
                    self.verification_locations
                ) >= 1
            ):
                confidence = Confidence.HIGH
            else:
                confidence = Confidence.MEDIUM

            reasons.append(
                "Payment/entitlement access is controlled "
                "through on-device boolean control-flow evidence."
            )

        # ==============================================================
        # Weak evidence: do NOT over-classify
        # ==============================================================

        else:
            has_billing_sdk = bool(
                self.billing
                and self.billing.providers_detected
            )

            has_boolean_candidates = any(
                candidate.status
                in (
                    StatusState.STRONG_CANDIDATE,
                    StatusState.POSSIBLE,
                )
                for candidate in (
                    self.boolean_candidates
                )
            )

            has_network_endpoints = bool(
                self.endpoints
            )

            if (
                has_billing_sdk
                or has_boolean_candidates
                or has_network_endpoints
            ):
                classification = (
                    ClassificationType.UNKNOWN
                )
                confidence = Confidence.LOW

                weak_sources = []

                if has_billing_sdk:
                    weak_sources.append(
                        "billing SDK presence"
                    )

                if has_boolean_candidates:
                    weak_sources.append(
                        "unconfirmed boolean candidates"
                    )

                if has_network_endpoints:
                    weak_sources.append(
                        "network endpoints without correlated verification flow"
                    )

                reasons.append(
                    "Relevant payment/entitlement artifacts "
                    "were detected, but they do not establish "
                    "a proven server-side or client-side "
                    "verification data flow. "
                    "Sources: "
                    + ", ".join(
                        weak_sources
                    )
                )
            else:
                classification = (
                    ClassificationType.UNKNOWN
                )
                confidence = Confidence.LOW

                reasons.append(
                    "Insufficient static evidence to classify "
                    "the payment verification architecture."
                )

        # ==============================================================
        # Additional diagnostic reasons
        # ==============================================================

        if (
            self.billing
            and self.billing.providers_detected
        ):
            reasons.append(
                "Detected billing providers: "
                + ", ".join(
                    self.billing.providers_detected
                )
            )

        if self.verification_locations:
            reasons.append(
                f"Found "
                f"{len(self.verification_locations)} "
                "boolean verification call-site(s)."
            )

        # Deduplicate while preserving order.
        reasons = list(
            dict.fromkeys(
                reasons
            )
        )

        return ClassificationFinding(
            classification=classification,
            confidence=confidence,
            reasons=reasons,
            server_side_evidence=server_evidence,
            client_side_evidence=client_evidence,
        )
