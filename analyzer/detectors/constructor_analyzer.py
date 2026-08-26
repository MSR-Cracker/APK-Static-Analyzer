"""Constructor Analyzer: Inspects <init> and <clinit> methods for state bootstrapping, local caching, and verification."""
from typing import List, Dict, Set
from analyzer.models import DexMethod, ConstructorFinding
from analyzer.detectors.base import BaseDetector


class ConstructorAnalyzer(BaseDetector):
    """Analyzes class constructors to determine whether premium state or billing verification occurs at instantiation."""

    def detect(self) -> List[ConstructorFinding]:
        findings: List[ConstructorFinding] = []

        # Find constructors of candidate / monetization classes
        constructors = [m for m in self.methods if m.is_constructor]

        for m in constructors:
            c_lower = m.class_name.lower()
            is_monetization_class = any(
                k in c_lower for k in [
                    "billing", "purchase", "premium", "subscription", "entitlement", "license",
                    "paywall", "checkout", "inapp", "useraccount", "session"
                ]
            )

            # Check for specific behaviors in constructor instructions and callees
            initializes_billing = False
            sets_premium = False
            reads_local = False
            loads_remote = False
            has_network = False
            evidence: List[str] = []

            for callee in m.callees:
                callee_lower = callee.lower()
                # 1. Billing SDK builder / initialization (Note: this is SDK init, NOT premium verification!)
                if "billingclient" in callee_lower or "purchases" in callee_lower or "newbuilder" in callee_lower:
                    initializes_billing = True
                    evidence.append(f"Initializes Billing SDK client: '{callee}' (SDK initialization, not direct verification)")

                # 2. Local state / SharedPreferences access
                if "sharedpreferences" in callee_lower or "getboolean" in callee_lower or "preferences" in callee_lower:
                    reads_local = True
                    evidence.append(f"Reads stored state from SharedPreferences/local store: '{callee}'")

                # 3. Network interaction
                if any(net in callee_lower for net in ["retrofit", "okhttp", "httpurlconnection", "volley"]):
                    has_network = True
                    evidence.append(f"Executes network call during constructor: '{callee}'")

            # Check field assignments in instructions (iput / sput)
            assigned_fields: List[str] = []
            for inst in m.instructions:
                if inst.opcode_name.startswith("iput") or inst.opcode_name.startswith("sput"):
                    if inst.referenced_field:
                        f_lower = inst.referenced_field.lower()
                        if any(kw in f_lower for kw in ["premium", "pro", "vip", "purchased", "entitled", "is_sub"]):
                            sets_premium = True
                            assigned_fields.append(inst.referenced_field)

            if assigned_fields:
                evidence.append(f"Directly assigns premium entitlement fields: {assigned_fields[:2]}")

            if not (is_monetization_class or sets_premium or reads_local or initializes_billing):
                continue

            # Verification Decision:
            # Setting BillingClient.newBuilder() is NOT verification.
            # Only mark YES if it actually verifies entitlement via local cache or network in constructor.
            verification = "NO"
            if sets_premium and reads_local:
                verification = "YES"
                evidence.append("Constructor actively verifies and initializes premium status from local storage")
            elif sets_premium and has_network:
                verification = "YES"
                evidence.append("Constructor triggers remote entitlement sync to establish premium status")
            elif initializes_billing and not sets_premium:
                verification = "NO"
                evidence.append("Constructor only bootstraps the BillingClient SDK without performing entitlement verification")
            elif sets_premium:
                verification = "UNKNOWN"
                evidence.append("Constructor sets premium fields with default values")
            else:
                verification = "NO"

            network_interaction = "YES" if has_network else "NO"
            field_name = assigned_fields[0] if assigned_fields else ""

            findings.append(ConstructorFinding(
                dex_file=m.dex_file,
                class_name=m.class_name,
                constructor_signature=f"{m.method_name}{m.signature}",
                verification=verification,
                network_interaction=network_interaction,
                source_apk=m.source_apk,
                initializes_billing_client=initializes_billing,
                sets_premium_flags=sets_premium,
                reads_local_state=reads_local,
                loads_remote_config=loads_remote,
                called_methods=m.callees,
                evidence=evidence,
                boolean_field_initialized=field_name,
                snippet=m.bytecode_snippet,
            ))

        # Prioritize findings with verification == YES or sets_premium == True
        findings.sort(key=lambda x: (1 if x.verification == "YES" else (2 if x.sets_premium_flags else 3)))
        return findings
