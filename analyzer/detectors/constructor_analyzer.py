"""Constructor Analyzer: Inspects <init> methods for purchase state setup, verification, local caching, and remote configs."""
from typing import List, Dict, Set
from analyzer.models import DexMethod, ConstructorFinding
from analyzer.detectors.base import BaseDetector


class ConstructorAnalyzer(BaseDetector):
    """Deeply evaluates <init> constructors of billing-related and manager classes."""

    def detect(self) -> List[ConstructorFinding]:
        findings: List[ConstructorFinding] = []
        
        # Filter for constructors in billing/manager/store classes
        constructors = [
            m for m in self.methods
            if m.is_constructor and (
                any(k in m.class_name.lower() for k in ["billing", "purchase", "subscription", "premium", "store", "iap", "licens", "manager"])
                or any(k in "".join(m.strings_referenced).lower() for k in ["billing", "premium", "purchase", "sku", "license"])
            )
        ]

        for c in constructors:
            evidence: List[str] = []
            initializes_billing_client = False
            sets_premium_flags = False
            reads_local_state = False
            loads_remote_config = False
            has_network_call = False
            is_verification = False

            # Check callees
            for callee in c.callees:
                callee_lower = callee.lower()

                if "billingclient" in callee_lower or "newbuilder" in callee_lower:
                    initializes_billing_client = True
                    evidence.append("Initializes BillingClient instance via builder")

                if "setpurchasesupdatedlistener" in callee_lower or "purchasesupdatedlistener" in callee_lower:
                    evidence.append("Registers PurchasesUpdatedListener callback")

                if "sharedpreferences" in callee_lower or "getboolean" in callee_lower or "pref" in callee_lower:
                    reads_local_state = True
                    evidence.append("Reads local SharedPreferences for initial cached entitlement state")

                if "firebase" in callee_lower or "remoteconfig" in callee_lower or "fetchandactivate" in callee_lower:
                    loads_remote_config = True
                    evidence.append("Loads remote configuration / feature flags on startup")

                if any(net in callee_lower for net in ["httpurlconnection", "okhttp", "retrofit", "volley", "execute", "enqueue"]):
                    has_network_call = True
                    evidence.append("Executes synchronous/asynchronous HTTP network request inside constructor")

                if any(v in callee_lower for v in ["verifypurchase", "validateentitlement", "checklicense", "querypurchases"]):
                    is_verification = True
                    evidence.append(f"Invokes verification/query routine: {callee}")

            # Check strings referenced
            for s in c.strings_referenced:
                s_lower = s.lower()
                if "is_premium" in s_lower or "pro_unlocked" in s_lower or "purchased" in s_lower:
                    sets_premium_flags = True
                    evidence.append(f"References entitlement key string '{s}'")
                if "https://" in s_lower or "http://" in s_lower:
                    has_network_call = True
                    evidence.append(f"Contains hardcoded remote URL: {s}")

            # Determine verification status (Careful: BillingClient init is NOT verification)
            if is_verification and (has_network_call or reads_local_state):
                verification_status = "YES"
            elif initializes_billing_client and not is_verification and not has_network_call:
                verification_status = "NO"
                evidence.append("Constructor only prepares client connection without validating ownership")
            elif not evidence:
                verification_status = "UNKNOWN"
            else:
                verification_status = "NO" if not is_verification else "YES"

            network_status = "YES" if has_network_call else "NO"

            finding = ConstructorFinding(
                dex_file=c.dex_file,
                class_name=c.class_name,
                constructor_signature=c.signature,
                verification=verification_status,
                network_interaction=network_status,
                initializes_billing_client=initializes_billing_client,
                sets_premium_flags=sets_premium_flags,
                reads_local_state=reads_local_state,
                loads_remote_config=loads_remote_config,
                called_methods=c.callees[:6],
                evidence=evidence if evidence else ["Standard object lifecycle initialization"],
                snippet=c.bytecode_snippet,
            )
            findings.append(finding)

        return findings
