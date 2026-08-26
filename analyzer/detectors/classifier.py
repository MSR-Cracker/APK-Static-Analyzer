"""Classifier: Classifies payment architecture into SERVER_SIDE, CLIENT_SIDE, MIXED, or UNKNOWN based strictly on proven data flow."""
from typing import List, Dict, Optional
from analyzer.models import (
    ClassificationFinding, ClassificationType, Confidence,
    BillingFinding, BooleanMethodCandidate, NetworkEndpoint, ConstructorFinding,
    BooleanVerificationLocation, CallSiteFinding, StatusState
)


class PaymentArchitectureClassifier:
    """Evaluates static analysis evidence to classify payment verification architecture strictly on facts."""

    def __init__(
        self,
        billing: BillingFinding,
        boolean_candidates: List[BooleanMethodCandidate],
        endpoints: List[NetworkEndpoint],
        constructors: List[ConstructorFinding],
        verification_locations: Optional[List[BooleanVerificationLocation]] = None,
        call_sites: Optional[List[CallSiteFinding]] = None,
    ):
        self.billing = billing
        self.boolean_candidates = boolean_candidates
        self.endpoints = endpoints
        self.constructors = constructors
        self.verification_locations = verification_locations or []
        self.call_sites = call_sites or []

    def classify(self) -> ClassificationFinding:
        server_evidence: List[str] = []
        client_evidence: List[str] = []

        # 1. Server-Side Analysis:
        # A URL string alone (even /verify) does NOT constitute proof of SERVER_SIDE architecture!
        # Must have verified network calls linked to entitlement verification or backend SDKs.
        if self.billing.has_revenuecat:
            server_evidence.append("Uses RevenueCat backend SDK for server-authoritative entitlement synchronization")

        for c in self.boolean_candidates:
            for callee in c.callees:
                if any(kw in callee.lower() for kw in ["verifyserver", "validatereceipt", "apiclient", "checkentitlement", "syncsubscription"]):
                    server_evidence.append(f"Boolean gate '{c.method_name}' delegates to remote verification routine '{callee}'")

        # Check for constructors executing verified remote network verification
        for ctor in self.constructors:
            if ctor.verification == "YES" and ctor.network_interaction == "YES":
                server_evidence.append(f"Constructor in '{ctor.class_name}' executes remote network verification upon instantiation")

        # 2. Client-Side Analysis:
        # Check verified boolean verification locations (control-flow branch gating on device)
        if self.verification_locations:
            for v in self.verification_locations:
                client_evidence.append(
                    f"Local control-flow branch gate in '{v.class_name}->{v.method_name}' branch on '{v.called_boolean_method}' ({v.branch_opcode})"
                )

        # Check candidates with local SharedPreferences / cache queries
        for c in self.boolean_candidates:
            if c.status == StatusState.CONFIRMED:
                for ev in c.purchase_relevance_evidence:
                    if "SharedPreferences" in ev or "local" in ev.lower():
                        client_evidence.append(f"Confirmed boolean method '{c.class_name}->{c.method_name}' queries local device storage")

        # Check constructors initializing local state
        for ctor in self.constructors:
            if ctor.verification == "YES" and ctor.reads_local_state:
                client_evidence.append(f"Constructor in '{ctor.class_name}' validates and initializes entitlement from local device preferences")

        # 3. Decision Matrix
        classification = ClassificationType.UNKNOWN
        confidence = Confidence.LOW
        reasons: List[str] = []

        if server_evidence and client_evidence:
            classification = ClassificationType.MIXED
            confidence = Confidence.HIGH if (len(server_evidence) >= 1 and len(client_evidence) >= 1) else Confidence.MEDIUM
            reasons.append(
                "Application uses both local client-side boolean control-flow gating and server-side verification pathways."
            )
        elif server_evidence and not client_evidence:
            classification = ClassificationType.SERVER_SIDE
            confidence = Confidence.HIGH if len(server_evidence) >= 2 else Confidence.MEDIUM
            reasons.append(
                "Entitlement decisions are delegated to remote backend API services with no local bypass gates found."
            )
        elif client_evidence and not server_evidence:
            classification = ClassificationType.CLIENT_SIDE
            confidence = Confidence.HIGH if len(self.verification_locations) >= 1 else Confidence.MEDIUM
            reasons.append(
                "Entitlement is gated entirely on-device via local boolean logic and Dalvik conditional branch instructions."
            )
        else:
            # If no confirmed call sites, no verified network flow, but billing SDK exists
            if self.billing.providers_detected and any(c.status in (StatusState.STRONG_CANDIDATE, StatusState.POSSIBLE) for c in self.boolean_candidates):
                classification = ClassificationType.UNKNOWN
                confidence = Confidence.LOW
                reasons.append(
                    "Billing SDK and boolean candidates detected, but no verified active call sites or data-flow linkages located (classified as UNKNOWN)."
                )
            else:
                classification = ClassificationType.UNKNOWN
                confidence = Confidence.LOW
                reasons.append(
                    "Insufficient static evidence to definitively classify payment verification model."
                )

        return ClassificationFinding(
            classification=classification,
            confidence=confidence,
            reasons=reasons,
            server_side_evidence=server_evidence,
            client_side_evidence=client_evidence,
        )
