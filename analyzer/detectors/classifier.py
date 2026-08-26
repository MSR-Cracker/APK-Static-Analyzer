"""Classifier: Classifies payment architecture into SERVER_SIDE, CLIENT_SIDE, MIXED, or UNKNOWN."""
from typing import List, Dict
from analyzer.models import (
    ClassificationFinding, ClassificationType, Confidence,
    BillingFinding, BooleanMethodCandidate, NetworkEndpoint, ConstructorFinding
)


class PaymentArchitectureClassifier:
    """Evaluates static analysis evidence to classify payment verification architecture."""

    def __init__(
        self,
        billing: BillingFinding,
        boolean_candidates: List[BooleanMethodCandidate],
        endpoints: List[NetworkEndpoint],
        constructors: List[ConstructorFinding],
    ):
        self.billing = billing
        self.boolean_candidates = boolean_candidates
        self.endpoints = endpoints
        self.constructors = constructors

    def classify(self) -> ClassificationFinding:
        server_evidence: List[str] = []
        client_evidence: List[str] = []

        # 1. Check Server-Side indicators
        purchase_endpoints = [e for e in self.endpoints if e.is_purchase_related]
        if purchase_endpoints:
            server_evidence.append(
                f"Application references remote purchase validation endpoints: {[e.url for e in purchase_endpoints[:3]]}"
            )

        if self.billing.has_revenuecat:
            server_evidence.append("Uses RevenueCat backend SDK for server-authoritative entitlement synchronization")

        for c in self.boolean_candidates:
            for callee in c.callees:
                if any(kw in callee.lower() for kw in ["verifyserver", "validatereceipt", "apiclient", "network", "remote"]):
                    server_evidence.append(f"Boolean check {c.method_name} delegates to remote service routine '{callee}'")

        # 2. Check Client-Side indicators
        for c in self.boolean_candidates:
            for ev in c.purchase_relevance_evidence:
                if "SharedPreferences" in ev or "local" in ev.lower():
                    client_evidence.append(f"Boolean check '{c.class_name}->{c.method_name}' evaluates local storage/preferences directly")

        for b in self.billing.evidence:
            if "acknowledgePurchase" in b or "consumePurchase" in b:
                client_evidence.append("App directly acknowledges/consumes purchases locally on device")

        for ctor in self.constructors:
            if ctor.reads_local_state:
                client_evidence.append(f"Constructor in '{ctor.class_name}' bootstraps entitlement from local device preferences")

        # Decision Matrix
        classification = ClassificationType.UNKNOWN
        confidence = Confidence.LOW
        reasons: List[str] = []

        if server_evidence and client_evidence:
            classification = ClassificationType.MIXED
            confidence = Confidence.HIGH if len(server_evidence) >= 2 and len(client_evidence) >= 2 else Confidence.MEDIUM
            reasons.append("App utilizes both local caching / client-side BillingClient handlers and server-side receipt validation APIs.")
        elif server_evidence and not client_evidence:
            classification = ClassificationType.SERVER_SIDE
            confidence = Confidence.HIGH if len(server_evidence) >= 2 else Confidence.MEDIUM
            reasons.append("Entitlement verification is delegated to remote backend API servers without local standalone override.")
        elif client_evidence and not server_evidence:
            classification = ClassificationType.CLIENT_SIDE
            confidence = Confidence.HIGH if len(client_evidence) >= 2 else Confidence.MEDIUM
            reasons.append("Purchase entitlement is determined entirely on-device using local flags, SharedPreferences, or local client verification.")
        else:
            if self.billing.providers_detected:
                classification = ClassificationType.CLIENT_SIDE
                confidence = Confidence.LOW
                reasons.append("Billing SDK detected but lack of remote verification endpoints points to standard client-side implementation.")
            else:
                classification = ClassificationType.UNKNOWN
                confidence = Confidence.LOW
                reasons.append("Insufficient static evidence to definitively classify payment verification model.")

        return ClassificationFinding(
            classification=classification,
            confidence=confidence,
            reasons=reasons,
            server_side_evidence=server_evidence,
            client_side_evidence=client_evidence,
        )
