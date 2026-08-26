"""Boolean Method Detector: Identifies and ranks purchase, entitlement, and premium gate boolean methods."""
import re
from typing import List, Dict, Set, Tuple
from analyzer.models import DexMethod, BooleanMethodCandidate, Confidence, StatusState
from analyzer.detectors.base import BaseDetector


class BooleanMethodDetector(BaseDetector):
    """Deep detector that analyzes method signatures, return types, field accesses, callers, and callees."""

    PREMIUM_METHOD_KEYWORDS = {
        "ispremium": 4.5,
        "ispro": 4.5,
        "isvip": 4.0,
        "issubscribed": 4.5,
        "haspurchased": 4.5,
        "isunlocked": 4.0,
        "ispurchased": 4.5,
        "haspremium": 4.5,
        "haslicense": 4.0,
        "isvalidlicense": 4.5,
        "isadfree": 4.0,
        "checkpremium": 4.0,
        "checklicense": 4.0,
        "isfeaturesupported": 2.5,
        "isfeatureenabled": 3.0,
        "canaccess": 3.0,
        "isactive": 2.5,
        "isvalid": 2.5,
        "getispremium": 4.0,
        "getispro": 4.0,
        "hasactiveentitlement": 5.0,
        "isentitled": 4.5,
    }

    BILLING_SDK_CALLEES = {
        "billingclient": 3.5,
        "querypurchases": 4.0,
        "querypurchasesasync": 4.5,
        "getpurchases": 3.5,
        "purchasestate": 3.5,
        "customerinfo": 4.0,
        "activeentitlements": 4.5,
        "hasactiveentitlement": 4.5,
        "iinappbillingservice": 4.0,
        "getpurchasestate": 4.0,
    }

    LOCAL_STORAGE_CALLEES = {
        "sharedpreferences": 2.5,
        "getboolean": 2.5,
        "preferences": 1.5,
        "datastore": 2.0,
        "room": 1.5,
        "sqlite": 1.5,
    }

    def detect(self) -> List[BooleanMethodCandidate]:
        candidates: List[BooleanMethodCandidate] = []

        for m in self.methods:
            # Must return boolean (Z or boolean)
            is_bool_return = (
                m.return_type == "boolean"
                or m.return_type == "Z"
                or m.signature.endswith(")Z")
            )
            if not is_bool_return:
                continue

            score = 0.0
            evidence: List[str] = []
            m_lower = m.method_name.lower()
            c_lower = m.class_name.lower()

            # 1. Method name keywords
            for kw, kw_score in self.PREMIUM_METHOD_KEYWORDS.items():
                if kw in m_lower:
                    score += kw_score
                    evidence.append(f"Method name matches key entitlement pattern: '{kw}' (+{kw_score})")
                    break

            # 2. Enclosing class semantic relevance
            if any(k in c_lower for k in ["premium", "billing", "purchase", "subscription", "license", "entitlement", "paywall"]):
                score += 3.0
                evidence.append(f"Enclosing class '{m.class_name}' is a dedicated monetization/entitlement container (+3.0)")
            elif any(k in c_lower for k in ["user", "account", "profile", "auth", "session", "config", "app"]):
                score += 1.0
                evidence.append(f"Enclosing class '{m.class_name}' is user/account state container (+1.0)")

            # 3. Callee analysis (Billing SDK APIs)
            for callee in m.callees:
                callee_lower = callee.lower()
                for b_kw, b_score in self.BILLING_SDK_CALLEES.items():
                    if b_kw in callee_lower:
                        score += b_score
                        evidence.append(f"Directly queries In-App Billing API: '{callee}' (+{b_score})")
                        break
                for s_kw, s_score in self.LOCAL_STORAGE_CALLEES.items():
                    if s_kw in callee_lower:
                        score += s_score
                        evidence.append(f"Queries local storage/preferences API: '{callee}' (+{s_score})")
                        break

            # 4. Field references
            for f in m.fields_referenced:
                f_lower = f.lower()
                if any(k in f_lower for k in ["premium", "pro", "vip", "purchased", "subscribed", "entitlement", "license", "billing"]):
                    score += 2.5
                    evidence.append(f"Accesses internal premium/license field: '{f}' (+2.5)")

            # 5. String constants referenced
            for s in m.strings_referenced:
                s_lower = s.lower()
                if any(k in s_lower for k in ["is_premium", "is_pro", "premium_user", "purchased", "subscription_id", "sku", "order_id"]):
                    score += 2.0
                    evidence.append(f"References monetization string constant: '{s}' (+2.0)")

            # 6. Callers (Cross-DEX Usage)
            if len(m.callers) > 0:
                score += min(len(m.callers) * 0.5, 3.0)
                ui_callers = [c for c in m.callers if any(k in c.lower() for k in ["activity", "fragment", "view", "ui", "main", "dialog"])]
                if ui_callers:
                    score += 2.0
                    evidence.append(f"Directly called by UI components to gate features: {ui_callers[:2]} (+2.0)")

            # 7. Obfuscated / Compact Method Fallback
            if len(m.method_name) <= 2 and (score > 0 or len(m.callers) >= 2):
                if len(m.callers) >= 3:
                    score += 1.5
                    evidence.append(f"Short identifier with high cross-call frequency ({len(m.callers)} callers) indicates central boolean gate")

            # 8. Check return instructions (constant vs calculated)
            returns_const_true = any(
                i.opcode_name.startswith("const") and "#1" in i.operands
                for i in m.instructions
            )
            if returns_const_true:
                evidence.append("Bytecode contains literal const boolean assignment")

            if score < 2.0:
                continue

            confidence = Confidence.LOW
            status = StatusState.POSSIBLE
            if score >= 4.5:
                confidence = Confidence.HIGH
                status = StatusState.STRONG_CANDIDATE
            elif score >= 3.0:
                confidence = Confidence.MEDIUM
                status = StatusState.STRONG_CANDIDATE
            else:
                confidence = Confidence.LOW
                status = StatusState.POSSIBLE

            why = "; ".join(evidence[:3]) if evidence else "Boolean gate matching entitlement criteria"

            candidates.append(BooleanMethodCandidate(
                dex_file=m.dex_file,
                class_name=m.class_name,
                package=m.package,
                method_name=m.method_name,
                signature=m.signature,
                return_type=m.return_type,
                source_apk=m.source_apk,
                parameters=m.parameters,
                access_flags=m.access_flags,
                is_static=m.is_static,
                is_native=m.is_native,
                is_abstract=m.is_abstract,
                is_constructor=m.is_constructor,
                source_location=f"{m.class_name}->{m.method_name}",
                callers=m.callers,
                callees=m.callees,
                confidence=confidence,
                status=status,
                purchase_relevance_evidence=evidence,
                score=round(score, 1),
                decompiled_snippet=m.bytecode_snippet or m.decompiled_source,
                why_identified=why,
                analysis_quality=m.analysis_quality,
            ))

        # Sort descending by score
        candidates.sort(key=lambda x: x.score, reverse=True)
        return candidates
