"""Evidence Collector & Packaging Engine.

Collects static-analysis findings, assigns deterministic sequential evidence
IDs (E001, E002, ...), and builds a grounded evidence package for optional AI
reasoning.

The collector is intentionally loss-minimizing:
important findings are not silently discarded by arbitrary [:N] limits.
"""

from typing import List, Dict, Any, Optional

from analyzer.models import (
    EvidenceItem,
    Confidence,
    BillingFinding,
    BooleanMethodCandidate,
    BooleanVerificationLocation,
    CallSiteFinding,
    ConstructorFinding,
    NetworkEndpoint,
    ObfuscationAnalysis,
    ClassificationFinding,
    ClassLevelAnalysis,
)


class EvidenceCollector:
    """Collects, categorizes, and assigns sequential IDs to static facts."""

    def __init__(self):
        self.evidence_list: List[EvidenceItem] = []
        self._counter: int = 1

    # ------------------------------------------------------------------
    # ID generation
    # ------------------------------------------------------------------

    def _next_id(self) -> str:
        """Generate the next sequential evidence identifier."""

        evidence_id = (
            f"E{self._counter:03d}"
        )

        self._counter += 1

        return evidence_id

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _enum_value(
        value: Any,
        default: str = "UNKNOWN",
    ) -> str:
        """Safely extract an Enum value or return a string."""

        if value is None:
            return default

        if hasattr(
            value,
            "value",
        ):
            return str(
                value.value
            )

        return str(
            value
        )

    @staticmethod
    def _safe_list(
        value: Any,
    ) -> List[Any]:
        """Normalize an optional iterable to a list."""

        if value is None:
            return []

        if isinstance(
            value,
            list,
        ):
            return value

        try:
            return list(
                value
            )
        except Exception:
            return []

    @staticmethod
    def _confidence_from_relevance(
        relevance_level: str,
    ) -> Confidence:
        """Convert endpoint relevance into evidence confidence."""

        normalized = (
            relevance_level or ""
        ).upper()

        if normalized == "HIGH":
            return Confidence.HIGH

        if normalized == "MEDIUM":
            return Confidence.MEDIUM

        return Confidence.LOW

    def _append_evidence(
        self,
        *,
        category: str,
        summary: str,
        description: str,
        confidence: Confidence,
        dex_file: Optional[str] = None,
        class_name: Optional[str] = None,
        method_name: Optional[str] = None,
        offset: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create and register one EvidenceItem."""

        evidence_id = self._next_id()

        item = EvidenceItem(
            id=evidence_id,
            category=category,
            summary=summary,
            description=description,
            confidence=confidence,
            dex_file=dex_file,
            class_name=class_name,
            method_name=method_name,
            offset=offset,
            details=details or {},
        )

        self.evidence_list.append(
            item
        )

        return evidence_id

    # ------------------------------------------------------------------
    # Main collector
    # ------------------------------------------------------------------

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
        """
        Collect all meaningful static-analysis evidence.

        Evidence is intentionally not truncated to the first N findings.
        Ranking and filtering should happen at presentation time rather than
        silently destroying evidence at collection time.
        """

        self.evidence_list = []
        self._counter = 1

        # ==============================================================
        # 1. Billing SDK / Billing architecture
        # ==============================================================

        if billing:
            providers = self._safe_list(
                billing.providers_detected
            )

            billing_evidence = self._safe_list(
                billing.evidence
            )

            if providers or billing_evidence:
                details = {
                    "providers": providers,
                    "classes": self._safe_list(
                        billing.billing_classes
                    ),
                    "methods": self._safe_list(
                        billing.billing_methods
                    ),
                    "google_play_version": (
                        billing.google_play_version
                    ),
                    "has_google_play": (
                        billing.has_google_play
                    ),
                    "has_aidl": (
                        billing.has_aidl
                    ),
                    "has_revenuecat": (
                        billing.has_revenuecat
                    ),
                    "has_qonversion": (
                        billing.has_qonversion
                    ),
                    "has_adapty": (
                        billing.has_adapty
                    ),
                    "has_custom": (
                        billing.has_custom
                    ),
                }

                evidence_id = (
                    self._append_evidence(
                        category="BILLING_SDK",
                        summary=(
                            "Detected billing providers: "
                            + (
                                ", ".join(
                                    providers
                                )
                                if providers
                                else "custom/unknown"
                            )
                        ),
                        description=(
                            "; ".join(
                                str(item)
                                for item in billing_evidence
                            )
                            if billing_evidence
                            else (
                                "Billing-related classes and "
                                "methods were detected."
                            )
                        ),
                        confidence=(
                            billing.confidence
                            if isinstance(
                                billing.confidence,
                                Confidence,
                            )
                            else Confidence.MEDIUM
                        ),
                        details=details,
                    )
                )

                billing.evidence_id = evidence_id

        # ==============================================================
        # 2. Obfuscation
        # ==============================================================

        if (
            obfuscation
            and (
                obfuscation.evidence
                or obfuscation.status
            )
        ):
            obfuscation_evidence = (
                self._safe_list(
                    obfuscation.evidence
                )
            )

            self._append_evidence(
                category="OBFUSCATION",
                summary=(
                    "Obfuscation status: "
                    f"{self._enum_value(obfuscation.status)}"
                ),
                description=(
                    "; ".join(
                        str(item)
                        for item in obfuscation_evidence
                    )
                    if obfuscation_evidence
                    else "Obfuscation analysis completed."
                ),
                confidence=(
                    obfuscation.confidence
                    if isinstance(
                        obfuscation.confidence,
                        Confidence,
                    )
                    else Confidence.LOW
                ),
                details={
                    "status": self._enum_value(
                        obfuscation.status
                    ),
                    "short_class_ratio": (
                        obfuscation.short_class_ratio
                    ),
                    "short_method_ratio": (
                        obfuscation.short_method_ratio
                    ),
                    "short_package_ratio": (
                        obfuscation.short_package_ratio
                    ),
                    "missing_debug_info_ratio": (
                        obfuscation.missing_debug_info_ratio
                    ),
                    "proguard_r8_patterns": (
                        self._safe_list(
                            obfuscation.proguard_r8_patterns
                        )
                    ),
                },
            )

        # ==============================================================
        # 3. Boolean method candidates
        # ==============================================================

        for candidate in (
            boolean_candidates
            or []
        ):
            candidate_evidence = (
                self._safe_list(
                    candidate.purchase_relevance_evidence
                )
            )

            evidence_id = (
                self._append_evidence(
                    category="BOOLEAN_METHOD",
                    summary=(
                        "Boolean gate candidate: "
                        f"{candidate.class_name}"
                        f"->{candidate.method_name}"
                        f"{candidate.signature}"
                    ),
                    description=(
                        candidate.why_identified
                        or (
                            f"Boolean method with score "
                            f"{candidate.score}."
                        )
                    ),
                    dex_file=candidate.dex_file,
                    class_name=candidate.class_name,
                    method_name=candidate.method_name,
                    confidence=(
                        candidate.confidence
                        if isinstance(
                            candidate.confidence,
                            Confidence,
                        )
                        else Confidence.MEDIUM
                    ),
                    details={
                        "score": candidate.score,
                        "return_type": candidate.return_type,
                        "status": self._enum_value(
                            candidate.status
                        ),
                        "confidence": self._enum_value(
                            candidate.confidence
                        ),
                        "callers": self._safe_list(
                            candidate.callers
                        ),
                        "callees": self._safe_list(
                            candidate.callees
                        ),
                        "callers_count": len(
                            candidate.callers or []
                        ),
                        "evidence_items": candidate_evidence,
                        "decompiled_snippet": (
                            candidate.decompiled_snippet
                        ),
                        "analysis_quality": (
                            candidate.analysis_quality
                        ),
                    },
                )
            )

            candidate.evidence_id = evidence_id

        # ==============================================================
        # 4. Verified boolean locations
        # ==============================================================

        for location in (
            verification_locations
            or []
        ):
            confidence = getattr(
                location,
                "confidence",
                Confidence.MEDIUM,
            )

            if not isinstance(
                confidence,
                Confidence,
            ):
                confidence = Confidence.MEDIUM

            location_evidence = (
                self._safe_list(
                    location.evidence
                )
            )

            evidence_id = (
                self._append_evidence(
                    category="VERIFICATION_CALL_SITE",
                    summary=(
                        "Boolean verification gate: "
                        f"{location.class_name}"
                        f"->{location.method_name} "
                        f"checks "
                        f"{location.called_boolean_class}"
                        f"->{location.called_boolean_method}"
                    ),
                    description=(
                        f"At offset "
                        f"0x{location.instruction_offset:04x}, "
                        f"the returned boolean is tested with "
                        f"{location.branch_opcode} on "
                        f"{location.result_register}. "
                        f"True target: "
                        f"{location.true_branch_target}; "
                        f"false/fallthrough target: "
                        f"{location.false_branch_target}."
                    ),
                    dex_file=location.dex_file,
                    class_name=location.class_name,
                    method_name=location.method_name,
                    offset=location.instruction_offset,
                    confidence=confidence,
                    details={
                        "called_class": (
                            location.called_boolean_class
                        ),
                        "called_method": (
                            location.called_boolean_method
                        ),
                        "branch_opcode": (
                            location.branch_opcode
                        ),
                        "result_register": (
                            location.result_register
                        ),
                        "true_effect": (
                            location.true_branch_effect
                        ),
                        "false_effect": (
                            location.false_branch_effect
                        ),
                        "tracked_registers": (
                            self._safe_list(
                                getattr(
                                    location,
                                    "tracked_registers",
                                    [],
                                )
                            )
                        ),
                        "verification_type": (
                            getattr(
                                location,
                                "verification_type",
                                "BOOLEAN_GATE",
                            )
                        ),
                        "evidence": location_evidence,
                        "bytecode_snippet": (
                            location.bytecode_snippet
                        ),
                    },
                )
            )

            location.evidence_id = evidence_id

        # ==============================================================
        # 5. Boolean call sites
        # ==============================================================

        for call_site in (
            call_sites
            or []
        ):
            # An existing evidence_id means it was already explicitly
            # assigned elsewhere. Do not duplicate it.
            if call_site.evidence_id:
                continue

            evidence_confidence = (
                Confidence.HIGH
                if (
                    getattr(
                        call_site,
                        "result_register_tested",
                        False,
                    )
                    or (
                        call_site.conditional_branch
                        is not None
                    )
                )
                else Confidence.MEDIUM
            )

            evidence_id = (
                self._append_evidence(
                    category="CALL_SITE",
                    summary=(
                        "Boolean call site: "
                        f"{call_site.caller_class}"
                        f"->{call_site.caller_method} "
                        "invokes "
                        f"{call_site.called_class}"
                        f"->{call_site.called_method}"
                    ),
                    description=(
                        call_site.effect_summary
                        or (
                            "Call at offset "
                            f"0x{call_site.instruction_offset:04x}."
                        )
                    ),
                    dex_file=call_site.dex_file,
                    class_name=call_site.caller_class,
                    method_name=call_site.caller_method,
                    offset=call_site.instruction_offset,
                    confidence=evidence_confidence,
                    details={
                        "called_class": (
                            call_site.called_class
                        ),
                        "called_method": (
                            call_site.called_method
                        ),
                        "called_signature": (
                            call_site.called_signature
                        ),
                        "arguments": self._safe_list(
                            call_site.arguments
                        ),
                        "move_result_register": (
                            call_site.move_result_register
                        ),
                        "tracked_registers": (
                            self._safe_list(
                                getattr(
                                    call_site,
                                    "tracked_registers",
                                    [],
                                )
                            )
                        ),
                        "conditional_branch": (
                            call_site.conditional_branch
                        ),
                        "branch_offset": (
                            call_site.branch_offset
                        ),
                        "true_branch_target": (
                            call_site.true_branch_target
                        ),
                        "false_branch_target": (
                            call_site.false_branch_target
                        ),
                        "true_branch_effect": (
                            call_site.true_branch_effect
                        ),
                        "false_branch_effect": (
                            call_site.false_branch_effect
                        ),
                        "verification_type": (
                            getattr(
                                call_site,
                                "verification_type",
                                "UNKNOWN",
                            )
                        ),
                        "result_register_tested": (
                            getattr(
                                call_site,
                                "result_register_tested",
                                False,
                            )
                        ),
                    },
                )
            )

            call_site.evidence_id = evidence_id

        # ==============================================================
        # 6. Constructor analysis
        # ==============================================================

        for constructor in (
            constructors
            or []
        ):
            constructor_evidence = (
                self._safe_list(
                    constructor.evidence
                )
            )

            confidence = (
                Confidence.HIGH
                if constructor.verification
                == "YES"
                else (
                    Confidence.MEDIUM
                    if constructor.verification
                    == "UNKNOWN"
                    else Confidence.LOW
                )
            )

            evidence_id = (
                self._append_evidence(
                    category="CONSTRUCTOR_CHECK",
                    summary=(
                        "Constructor analysis: "
                        f"{constructor.class_name}"
                        "-><init>"
                    ),
                    description=(
                        f"Premium verification: "
                        f"{constructor.verification}; "
                        f"network interaction: "
                        f"{constructor.network_interaction}. "
                        + (
                            " ".join(
                                constructor_evidence
                            )
                            if constructor_evidence
                            else ""
                        )
                    ).strip(),
                    dex_file=constructor.dex_file,
                    class_name=constructor.class_name,
                    method_name="<init>",
                    confidence=confidence,
                    details={
                        "verification": (
                            constructor.verification
                        ),
                        "network_interaction": (
                            constructor.network_interaction
                        ),
                        "initializes_billing_client": (
                            constructor.initializes_billing_client
                        ),
                        "sets_premium_flags": (
                            constructor.sets_premium_flags
                        ),
                        "reads_local_state": (
                            constructor.reads_local_state
                        ),
                        "loads_remote_config": (
                            constructor.loads_remote_config
                        ),
                        "called_methods": (
                            self._safe_list(
                                constructor.called_methods
                            )
                        ),
                        "boolean_field_initialized": (
                            constructor.boolean_field_initialized
                        ),
                    },
                )
            )

            constructor.evidence_id = (
                evidence_id
            )

        # ==============================================================
        # 7. Network endpoints
        # ==============================================================

        for endpoint in (
            endpoints
            or []
        ):
            # All discovered endpoints are useful static facts.
            # Earlier code only recorded HIGH/MEDIUM endpoints, which could
            # make the report incomplete.
            evidence_confidence = (
                self._confidence_from_relevance(
                    endpoint.relevance_level
                )
            )

            endpoint_evidence = self._safe_list(
                getattr(
                    endpoint,
                    "evidence",
                    [],
                )
            )

            evidence_id = (
                self._append_evidence(
                    category="NETWORK_ENDPOINT",
                    summary=(
                        "Network endpoint: "
                        f"{endpoint.url}"
                    ),
                    description=(
                        endpoint.relevance_reason
                        or (
                            f"Domain {endpoint.domain} "
                            "was referenced from "
                            f"{endpoint.referenced_from_class}"
                            "->"
                            f"{endpoint.referenced_from_method}."
                        )
                    ),
                    dex_file=endpoint.dex_file,
                    class_name=(
                        endpoint.referenced_from_class
                    ),
                    method_name=(
                        endpoint.referenced_from_method
                    ),
                    confidence=evidence_confidence,
                    details={
                        "url": endpoint.url,
                        "domain": endpoint.domain,
                        "http_method": (
                            endpoint.http_method
                        ),
                        "client_library": (
                            endpoint.client_library
                        ),
                        "relevance_level": (
                            endpoint.relevance_level
                        ),
                        "is_purchase_related": (
                            endpoint.is_purchase_related
                        ),
                        "evidence": endpoint_evidence,
                        "locations": (
                            self._safe_list(
                                getattr(
                                    endpoint,
                                    "locations",
                                    [],
                                )
                            )
                        ),
                    },
                )
            )

            endpoint.evidence_id = (
                evidence_id
            )

        # ==============================================================
        # 8. Architecture classification
        # ==============================================================

        if classification:
            reasons = self._safe_list(
                classification.reasons
            )

            server_evidence = self._safe_list(
                classification.server_side_evidence
            )

            client_evidence = self._safe_list(
                classification.client_side_evidence
            )

            # Classification is itself a useful evidence item because it is
            # a synthesis of multiple static facts.
            self._append_evidence(
                category="ARCHITECTURE_CLASSIFICATION",
                summary=(
                    "Payment architecture: "
                    f"{self._enum_value(classification.classification)}"
                ),
                description=(
                    "; ".join(
                        str(item)
                        for item in reasons
                    )
                    if reasons
                    else "Static architecture classification."
                ),
                confidence=(
                    classification.confidence
                    if isinstance(
                        classification.confidence,
                        Confidence,
                    )
                    else Confidence.LOW
                ),
                details={
                    "classification": self._enum_value(
                        classification.classification
                    ),
                    "server_side_evidence": server_evidence,
                    "client_side_evidence": client_evidence,
                },
            )

        # ==============================================================
        # 9. Class-level analysis
        # ==============================================================

        if class_analysis:
            class_evidence = self._safe_list(
                class_analysis.evidence
            )

            if (
                class_analysis.primary_purchase_class
                or class_analysis.primary_premium_class
                or class_analysis.primary_boolean_method
                or class_evidence
            ):
                self._append_evidence(
                    category="CLASS_ANALYSIS",
                    summary=(
                        "Primary purchase/entitlement targets"
                    ),
                    description=(
                        "; ".join(
                            str(item)
                            for item in class_evidence
                        )
                        if class_evidence
                        else (
                            "Class-level analysis identified "
                            "purchase/entitlement targets."
                        )
                    ),
                    confidence=(
                        class_analysis.confidence
                        if isinstance(
                            class_analysis.confidence,
                            Confidence,
                        )
                        else Confidence.LOW
                    ),
                    class_name=(
                        class_analysis.primary_purchase_class
                        or class_analysis.primary_premium_class
                    ),
                    method_name=(
                        class_analysis.primary_boolean_method
                    ),
                    details={
                        "primary_purchase_class": (
                            class_analysis.primary_purchase_class
                        ),
                        "primary_premium_class": (
                            class_analysis.primary_premium_class
                        ),
                        "primary_boolean_method": (
                            class_analysis.primary_boolean_method
                        ),
                        "primary_boolean_dex": (
                            class_analysis.primary_boolean_dex
                        ),
                        "primary_boolean_signature": (
                            class_analysis.primary_boolean_signature
                        ),
                        "top_purchase_classes": (
                            self._safe_list(
                                class_analysis.top_purchase_classes
                            )
                        ),
                        "top_premium_classes": (
                            self._safe_list(
                                class_analysis.top_premium_classes
                            )
                        ),
                    },
                )

        return self.evidence_list

    # ------------------------------------------------------------------
    # Gemini evidence package
    # ------------------------------------------------------------------

    def build_gemini_evidence_package(
        self,
        package_name: str,
        input_type: str,
        total_dex: int,
        classification: Optional[ClassificationFinding],
        class_analysis: Optional[ClassLevelAnalysis],
    ) -> Dict[str, Any]:
        """
        Build a structured, evidence-ID-grounded package.

        Only already-collected evidence is exposed here, so Gemini cannot
        accidentally receive facts that lack an Evidence ID.
        """

        classification_data = {
            "architecture": (
                self._enum_value(
                    classification.classification
                )
                if classification
                else "UNKNOWN"
            ),
            "confidence": (
                self._enum_value(
                    classification.confidence
                )
                if classification
                else "LOW"
            ),
            "server_side_evidence": (
                self._safe_list(
                    classification.server_side_evidence
                )
                if classification
                else []
            ),
            "client_side_evidence": (
                self._safe_list(
                    classification.client_side_evidence
                )
                if classification
                else []
            ),
            "reasons": (
                self._safe_list(
                    classification.reasons
                )
                if classification
                else []
            ),
        }

        primary_targets = {
            "primary_purchase_class": (
                class_analysis.primary_purchase_class
                if class_analysis
                else None
            ),
            "primary_premium_class": (
                class_analysis.primary_premium_class
                if class_analysis
                else None
            ),
            "primary_boolean_method": (
                class_analysis.primary_boolean_method
                if class_analysis
                else None
            ),
            "primary_boolean_dex": (
                class_analysis.primary_boolean_dex
                if class_analysis
                else None
            ),
            "primary_boolean_signature": (
                class_analysis.primary_boolean_signature
                if class_analysis
                else None
            ),
        }

        inventory: List[
            Dict[str, Any]
        ] = []

        for item in self.evidence_list:
            inventory.append(
                {
                    "id": item.id,
                    "category": item.category,
                    "summary": item.summary,
                    "description": item.description,
                    "dex": item.dex_file,
                    "class": item.class_name,
                    "method": item.method_name,
                    "offset": (
                        f"0x{item.offset:04x}"
                        if item.offset is not None
                        else None
                    ),
                    "confidence": (
                        self._enum_value(
                            item.confidence,
                            "LOW",
                        )
                    ),
                    "details": item.details,
                }
            )

        return {
            "application_meta": {
                "package_name": package_name,
                "input_type": input_type,
                "total_dex_files": total_dex,
            },

            "static_classification": classification_data,

            "primary_targets": primary_targets,

            "evidence_inventory": inventory,

            "evidence_count": len(
                inventory
            ),
        }
