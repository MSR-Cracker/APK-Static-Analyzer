"""PurchaseBooleanDetector: Multi-DEX contextual locator for boolean purchase and entitlement verification methods."""
import re
from typing import List, Dict, Any, Tuple
from analyzer.models import DexMethod, BooleanMethodCandidate, Confidence, StatusState
from analyzer.detectors.base import BaseDetector


class PurchaseBooleanDetector(BaseDetector):
    """Deep contextual detector locating boolean purchase, premium, and subscription verification methods across all DEX files."""

    EXPLICIT_METHOD_KEYWORDS = [
        "ispurchased", "haspurchased", "ispremium", "ispro", "issubscribed",
        "ispaid", "isentitled", "checkpurchase", "verifypurchase", "hasvalidentitlement",
        "hasvalidsync", "isunlocked", "isvip", "isadfree", "isactive", "haslicense",
        "checksubscription", "isproversion", "ispremiumuser", "isfeaturesupported",
        "hasfeature", "isbillingready", "checkentitlement"
    ]

    BILLING_CLASS_KEYWORDS = [
        "billing", "purchase", "subscription", "premium", "entitlement",
        "store", "licens", "iap", "paywall", "order", "inapp", "featuregate"
    ]

    PURCHASE_STRING_KEYWORDS = [
        "premium", "purchased", "is_purchased", "is_pro", "is_premium",
        "subscription", "entitlement", "sku_pro", "sku_premium", "billing_client",
        "purchases_updated", "pref_purchase", "key_pro_status", "inapp_purchase",
        "receipt_data", "verified_purchase", "order_id", "token_verified"
    ]

    def detect(self) -> List[BooleanMethodCandidate]:
        candidates: List[BooleanMethodCandidate] = []

        for m in self.methods:
            # Must return boolean ("boolean" or "Z")
            if m.return_type != "boolean" and not m.signature.endswith("Z"):
                continue

            score = 0.0
            evidence: List[str] = []

            m_name_lower = m.method_name.lower()
            c_name_lower = m.class_name.lower()

            # 1. Method Name Context
            for kw in self.EXPLICIT_METHOD_KEYWORDS:
                if kw in m_name_lower:
                    score += 3.5
                    evidence.append(f"Method name '{m.method_name}' explicitly matches purchase keyword '{kw}'")
                    break

            # 2. Class Name Context
            for kw in self.BILLING_CLASS_KEYWORDS:
                if kw in c_name_lower:
                    score += 2.5
                    evidence.append(f"Enclosing class '{m.class_name}' is related to billing domain ('{kw}')")
                    break

            # 3. String References
            matched_strings = []
            for s in m.strings_referenced:
                s_lower = s.lower()
                for skw in self.PURCHASE_STRING_KEYWORDS:
                    if skw in s_lower:
                        matched_strings.append(s)
                        break
            if matched_strings:
                score += min(3.0, 1.2 * len(matched_strings))
                evidence.append(f"References purchase/entitlement strings: {matched_strings[:4]}")

            # 4. Callee Invocations (calls BillingClient, SharedPreferences, or Verification API)
            for callee in m.callees:
                callee_lower = callee.lower()
                if "billingclient" in callee_lower or "purchase" in callee_lower or "sku" in callee_lower:
                    score += 2.5
                    evidence.append(f"Invokes billing API method: {callee}")
                elif "sharedpreferences" in callee_lower and "getboolean" in callee_lower:
                    score += 1.5
                    evidence.append(f"Reads local SharedPreferences boolean state ({callee})")
                elif "verify" in callee_lower or "entitlement" in callee_lower:
                    score += 2.0
                    evidence.append(f"Calls internal verification logic: {callee}")

            # 5. Caller Context (called by Activities or UI Screens)
            activity_callers = [c for c in m.callers if "Activity" in c or "Fragment" in c or "UI" in c]
            if activity_callers:
                score += 1.5
                evidence.append(f"Called directly by UI/Activity gate: {activity_callers[:3]}")

            # 6. Parameter signature (e.g. ()Z is ideal for global purchase check, (String)Z for sku check)
            if len(m.parameters) == 0:
                score += 0.8
                evidence.append("Parameterless signature ()Z suitable for global entitlement status query")
            elif len(m.parameters) == 1 and m.parameters[0] in ("java.lang.String", "String"):
                score += 0.8
                evidence.append("Signature (String)Z suitable for SKU/Product specific entitlement query")

            # Obfuscation resilience: If class is short like a.b.c but references billing strings and called by Activity
            if len(m.class_name.split(".")[-1]) <= 2 and (len(evidence) >= 2 or score >= 3.0):
                score += 1.0
                evidence.append("Identified as obfuscated candidate with high contextual billing correlation")

            # Determine confidence & status
            if score >= 6.0:
                confidence = Confidence.HIGH
                status = StatusState.CONFIRMED if len(evidence) >= 3 else StatusState.STRONG_CANDIDATE
            elif score >= 3.5:
                confidence = Confidence.MEDIUM
                status = StatusState.STRONG_CANDIDATE
            elif score >= 1.5:
                confidence = Confidence.LOW
                status = StatusState.POSSIBLE
            else:
                continue

            # Build source location string
            source_loc = m.source_file or f"{m.class_name.replace('.', '/')}.java"

            candidate = BooleanMethodCandidate(
                dex_file=m.dex_file,
                class_name=m.class_name,
                package=m.package,
                method_name=m.method_name,
                signature=m.signature,
                return_type="boolean",
                parameters=m.parameters,
                access_flags=m.access_flags,
                is_static=m.is_static,
                is_native=m.is_native,
                is_abstract=m.is_abstract,
                is_constructor=m.is_constructor,
                source_location=source_loc,
                callers=m.callers[:8],
                callees=m.callees[:8],
                confidence=confidence,
                status=status,
                purchase_relevance_evidence=evidence,
                score=round(score, 2),
                decompiled_snippet=m.bytecode_snippet,
            )
            candidates.append(candidate)

        # Sort candidates descending by score
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates
