"""Evidence Collector & Packaging Engine: Assigns sequential IDs (E001, E002, ...) and formats grounded packages."""
from typing import List, Dict, Any, Optional
from analyzer.models import (
    EvidenceItem, Confidence, BillingFinding, BooleanMethodCandidate,
    BooleanVerificationLocation, CallSiteFinding, ConstructorFinding,
    NetworkEndpoint, ObfuscationAnalysis, ClassificationFinding, ClassLevelAnalysis
)


class EvidenceCollector:
    """Collects, categorizes, and assigns unique, sequential IDs to all static analysis facts."""

    def __init__(self):
        self.evidence_list: List[EvidenceItem] = []
        self._counter: int = 1

    def _next_id(self) -> str:
        eid = f"E{self._counter:03d}"
        self._counter += 1
        return eid

    def collect(
        self,
        billing: Optional[BillingFinding],
        boolean_candidates: List[BooleanMethodCandidate],
        verification_locations: List[BooleanVerificationLocation],
        call_sites: List[CallSiteFinding],
        constructors: List[ConstructorFinding],
        endpoints: List[NetworkEndpoint],
        obfuscation: Optional[ObfuscationAnalysis],
        classification: Optional[ClassificationFinding],
        class_analysis: Optional[ClassLevelAnalysis],
    ) -> List[EvidenceItem]:
        self.evidence_list = []
        self._counter = 1

        # 1. Billing SDK Evidence
        if billing and billing.providers_detected:
            eid = self._next_id()
            billing.evidence_id = eid
            self.evidence_list.append(EvidenceItem(
                id=eid,
                category="BILLING_SDK",
                summary=f"Detected Billing Providers: {', '.join(billing.providers_detected)}",
                description="; ".join(billing.evidence) or "In-App Billing libraries and APIs identified in DEX classes",
                confidence=billing.confidence,
                details={
                    "providers": billing.providers_detected,
                    "classes": billing.billing_classes[:5],
                    "google_play_version": billing.google_play_version,
                }
            ))

        # 2. Obfuscation Evidence
        if obfuscation and obfuscation.evidence:
            eid = self._next_id()
            self.evidence_list.append(EvidenceItem(
                id=eid,
                category="OBFUSCATION",
                summary=f"Obfuscation Status: {obfuscation.status.value}",
                description="; ".join(obfuscation.evidence),
                confidence=obfuscation.confidence,
                details={
                    "short_class_ratio": obfuscation.short_class_ratio,
                    "short_method_ratio": obfuscation.short_method_ratio,
                }
            ))

        # 3. Boolean Candidates Evidence
        for b in boolean_candidates[:8]:
            eid = self._next_id()
            b.evidence_id = eid
            self.evidence_list.append(EvidenceItem(
                id=eid,
                category="BOOLEAN_METHOD",
                summary=f"Boolean Gate Candidate: {b.class_name}->{b.method_name}{b.signature}",
                description=b.why_identified or f"Returns {b.return_type}, score: {b.score}",
                dex_file=b.dex_file,
                class_name=b.class_name,
                method_name=b.method_name,
                confidence=b.confidence,
                details={
                    "score": b.score,
                    "return_type": b.return_type,
                    "callers_count": len(b.callers),
                    "evidence_items": b.purchase_relevance_evidence,
                    "decompiled_snippet": b.decompiled_snippet,
                }
            ))

        # 4. Verification Locations Evidence
        for v in verification_locations[:6]:
            eid = self._next_id()
            v.evidence_id = eid
            self.evidence_list.append(EvidenceItem(
                id=eid,
                category="VERIFICATION_CALL_SITE",
                summary=f"Verification Gate: {v.class_name}->{v.method_name} checks {v.called_boolean_method}",
                description=(
                    f"At offset 0x{v.instruction_offset:04x}, uses {v.branch_opcode} on register {v.result_register}. "
                    f"True target: {v.true_branch_target} ({v.true_branch_effect}); False target: {v.false_branch_target} ({v.false_branch_effect})"
                ),
                dex_file=v.dex_file,
                class_name=v.class_name,
                method_name=v.method_name,
                offset=v.instruction_offset,
                confidence=Confidence.HIGH,
                details={
                    "called_class": v.called_boolean_class,
                    "called_method": v.called_boolean_method,
                    "branch_opcode": v.branch_opcode,
                    "result_register": v.result_register,
                    "true_effect": v.true_branch_effect,
                    "false_effect": v.false_branch_effect,
                    "bytecode_snippet": v.bytecode_snippet,
                }
            ))

        # 5. Call Sites Evidence
        for cs in call_sites[:6]:
            if not cs.evidence_id:
                eid = self._next_id()
                cs.evidence_id = eid
                self.evidence_list.append(EvidenceItem(
                    id=eid,
                    category="CALL_SITE",
                    summary=f"Call Site: {cs.caller_class}->{cs.caller_method} invokes {cs.called_method}",
                    description=cs.effect_summary or f"Call at offset 0x{cs.instruction_offset:04x} with move-result {cs.move_result_register}",
                    dex_file=cs.dex_file,
                    class_name=cs.caller_class,
                    method_name=cs.caller_method,
                    offset=cs.instruction_offset,
                    confidence=Confidence.HIGH,
                    details={
                        "move_result_register": cs.move_result_register,
                        "conditional_branch": cs.conditional_branch,
                        "true_branch_effect": cs.true_branch_effect,
                        "false_branch_effect": cs.false_branch_effect,
                    }
                ))

        # 6. Constructors Evidence
        for c in constructors[:6]:
            eid = self._next_id()
            c.evidence_id = eid
            self.evidence_list.append(EvidenceItem(
                id=eid,
                category="CONSTRUCTOR_CHECK",
                summary=f"Constructor: {c.class_name}-><init>",
                description=f"Premium verification: {c.verification}; Network interaction: {c.network_interaction}. Evidence: {'; '.join(c.evidence)}",
                dex_file=c.dex_file,
                class_name=c.class_name,
                confidence=Confidence.HIGH if c.verification == "YES" else Confidence.MEDIUM,
                details={
                    "verification": c.verification,
                    "network_interaction": c.network_interaction,
                    "initializes_billing_client": c.initializes_billing_client,
                    "sets_premium_flags": c.sets_premium_flags,
                    "reads_local_state": c.reads_local_state,
                }
            ))

        # 7. Network Endpoints Evidence
        for ep in endpoints:
            if ep.relevance_level in ("HIGH", "MEDIUM"):
                eid = self._next_id()
                ep.evidence_id = eid
                self.evidence_list.append(EvidenceItem(
                    id=eid,
                    category="NETWORK_ENDPOINT",
                    summary=f"Network Endpoint: {ep.url}",
                    description=ep.relevance_reason or f"Domain: {ep.domain}, referenced in {ep.referenced_from_class}",
                    dex_file=ep.dex_file,
                    class_name=ep.referenced_from_class,
                    method_name=ep.referenced_from_method,
                    confidence=Confidence.HIGH if ep.relevance_level == "HIGH" else Confidence.MEDIUM,
                    details={
                        "domain": ep.domain,
                        "client_library": ep.client_library,
                        "relevance_level": ep.relevance_level,
                    }
                ))

        return self.evidence_list

    def build_gemini_evidence_package(
        self,
        package_name: str,
        input_type: str,
        total_dex: int,
        classification: Optional[ClassificationFinding],
        class_analysis: Optional[ClassLevelAnalysis],
    ) -> Dict[str, Any]:
        """Builds a structured evidence package with exact Evidence IDs for Gemini grounding."""
        return {
            "application_meta": {
                "package_name": package_name,
                "input_type": input_type,
                "total_dex_files": total_dex,
            },
            "static_classification": {
                "architecture": classification.classification.value if classification else "UNKNOWN",
                "confidence": classification.confidence.value if classification else "LOW",
                "server_side_evidence": classification.server_side_evidence if classification else [],
                "client_side_evidence": classification.client_side_evidence if classification else [],
            },
            "primary_targets": {
                "primary_purchase_class": class_analysis.primary_purchase_class if class_analysis else None,
                "primary_premium_class": class_analysis.primary_premium_class if class_analysis else None,
                "primary_boolean_method": class_analysis.primary_boolean_method if class_analysis else None,
            },
            "evidence_inventory": [
                {
                    "id": item.id,
                    "category": item.category,
                    "summary": item.summary,
                    "description": item.description,
                    "dex": item.dex_file,
                    "class": item.class_name,
                    "method": item.method_name,
                    "offset": f"0x{item.offset:04x}" if item.offset is not None else None,
                    "confidence": item.confidence.value,
                    "details": item.details,
                }
                for item in self.evidence_list
            ],
        }
