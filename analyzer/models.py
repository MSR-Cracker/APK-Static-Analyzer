"""Data models for APK and APKS Static Analyzer."""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ClassificationType(str, Enum):
    SERVER_SIDE = "SERVER_SIDE"
    CLIENT_SIDE = "CLIENT_SIDE"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"


class StatusState(str, Enum):
    CONFIRMED = "CONFIRMED"
    STRONG_CANDIDATE = "STRONG_CANDIDATE"
    POSSIBLE = "POSSIBLE"
    NOT_FOUND = "NOT_FOUND"


class ObfuscationStatus(str, Enum):
    YES = "YES"
    NO = "NO"
    POSSIBLE = "POSSIBLE"


# ---------------------------------------------------------------------------
# Generic evidence
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    id: str
    category: str
    summary: str
    description: str
    confidence: Confidence = Confidence.HIGH
    dex_file: Optional[str] = None
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    offset: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# APKS / APK metadata
# ---------------------------------------------------------------------------

@dataclass
class ContainedApkInfo:
    name: str
    file_size_bytes: int = 0
    dex_count: int = 0
    is_base: bool = False
    split_type: str = "base"
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    permissions: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DEX metadata
# ---------------------------------------------------------------------------

@dataclass
class DexFileInfo:
    name: str
    source_apk: str = "base.apk"
    size_bytes: int = 0
    class_count: int = 0
    method_count: int = 0
    unsupported_opcodes_count: int = 0
    analysis_quality: str = "FULL"


# ---------------------------------------------------------------------------
# Instruction model
# ---------------------------------------------------------------------------

@dataclass
class InstructionDetail:
    offset: int
    opcode: int
    opcode_name: str
    raw_hex: str
    operands: str

    registers: List[str] = field(
        default_factory=list
    )

    branch_target: Optional[int] = None

    referenced_method: Optional[str] = None
    referenced_field: Optional[str] = None
    referenced_string: Optional[str] = None
    referenced_type: Optional[str] = None

    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": f"0x{self.offset:04x}",
            "opcode": self.opcode_name,
            "operands": self.operands,
            "registers": list(
                self.registers
            ),
            "branch_target": (
                f"0x{self.branch_target:04x}"
                if self.branch_target is not None
                else None
            ),
            "referenced_method": self.referenced_method,
            "referenced_field": self.referenced_field,
            "referenced_string": self.referenced_string,
            "referenced_type": self.referenced_type,
            "comment": self.comment,
        }


# ---------------------------------------------------------------------------
# DEX method
# ---------------------------------------------------------------------------

@dataclass
class DexMethod:
    dex_file: str
    class_name: str
    package: str
    method_name: str
    signature: str
    return_type: str

    source_apk: str = "base.apk"

    parameters: List[str] = field(
        default_factory=list
    )

    access_flags: List[str] = field(
        default_factory=list
    )

    is_static: bool = False
    is_native: bool = False
    is_abstract: bool = False
    is_constructor: bool = False

    source_file: Optional[str] = None
    line_number: Optional[int] = None

    callers: List[str] = field(
        default_factory=list
    )

    callees: List[str] = field(
        default_factory=list
    )

    strings_referenced: List[str] = field(
        default_factory=list
    )

    fields_referenced: List[str] = field(
        default_factory=list
    )

    types_referenced: List[str] = field(
        default_factory=list
    )

    branches: List[Dict[str, Any]] = field(
        default_factory=list
    )

    returns: List[Dict[str, Any]] = field(
        default_factory=list
    )

    bytecode_snippet: Optional[str] = None

    decompiled_source: Optional[str] = None

    instructions: List[InstructionDetail] = field(
        default_factory=list
    )

    unsupported_opcodes: List[Dict[str, Any]] = field(
        default_factory=list
    )

    analysis_quality: str = "FULL"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the method into the analyzer's canonical representation."""

        return {
            "dex": self.dex_file,
            "class": self.class_name,
            "package": self.package,
            "method": self.method_name,
            "signature": self.signature,
            "return_type": self.return_type,
            "source_apk": self.source_apk,
            "parameters": list(
                self.parameters
            ),
            "access": list(
                self.access_flags
            ),
            "is_static": self.is_static,
            "is_native": self.is_native,
            "is_abstract": self.is_abstract,
            "is_constructor": self.is_constructor,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "callers": list(
                self.callers
            ),
            "called_methods": list(
                self.callees
            ),
            "referenced_fields": list(
                self.fields_referenced
            ),
            "strings": list(
                self.strings_referenced
            ),
            "types": list(
                self.types_referenced
            ),
            "instructions": [
                instruction.to_dict()
                for instruction in self.instructions
            ],
            "branches": list(
                self.branches
            ),
            "returns": list(
                self.returns
            ),
            "bytecode_snippet": self.bytecode_snippet,
            "decompiled_source": self.decompiled_source,
            "unsupported_opcodes": list(
                self.unsupported_opcodes
            ),
            "analysis_quality": self.analysis_quality,
        }


# ---------------------------------------------------------------------------
# Obfuscation
# ---------------------------------------------------------------------------

@dataclass
class ObfuscationAnalysis:
    status: ObfuscationStatus = ObfuscationStatus.NO
    confidence: Confidence = Confidence.LOW

    evidence: List[str] = field(
        default_factory=list
    )

    short_class_ratio: float = 0.0
    short_method_ratio: float = 0.0
    short_package_ratio: float = 0.0

    missing_debug_info_ratio: float = 0.0

    proguard_r8_patterns: List[str] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Boolean method candidates
# ---------------------------------------------------------------------------

@dataclass
class BooleanMethodCandidate:
    dex_file: str
    class_name: str
    package: str
    method_name: str
    signature: str
    return_type: str

    source_apk: str = "base.apk"

    parameters: List[str] = field(
        default_factory=list
    )

    access_flags: List[str] = field(
        default_factory=list
    )

    is_static: bool = False
    is_native: bool = False
    is_abstract: bool = False
    is_constructor: bool = False

    source_location: str = ""

    callers: List[str] = field(
        default_factory=list
    )

    callees: List[str] = field(
        default_factory=list
    )

    confidence: Confidence = Confidence.MEDIUM
    status: StatusState = StatusState.POSSIBLE

    purchase_relevance_evidence: List[str] = field(
        default_factory=list
    )

    score: float = 0.0

    decompiled_snippet: Optional[str] = None

    why_identified: str = ""

    evidence_id: Optional[str] = None

    analysis_quality: str = "FULL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dex": self.dex_file,
            "class": self.class_name,
            "package": self.package,
            "method": self.method_name,
            "signature": self.signature,
            "return_type": self.return_type,
            "source_apk": self.source_apk,
            "parameters": list(
                self.parameters
            ),
            "access_flags": list(
                self.access_flags
            ),
            "callers": list(
                self.callers
            ),
            "callees": list(
                self.callees
            ),
            "confidence": self.confidence.value
            if isinstance(
                self.confidence,
                Confidence,
            )
            else self.confidence,
            "status": self.status.value
            if isinstance(
                self.status,
                StatusState,
            )
            else self.status,
            "purchase_relevance_evidence": list(
                self.purchase_relevance_evidence
            ),
            "score": self.score,
            "decompiled_snippet": self.decompiled_snippet,
            "why_identified": self.why_identified,
            "evidence_id": self.evidence_id,
            "analysis_quality": self.analysis_quality,
        }


# ---------------------------------------------------------------------------
# Verification call site
# ---------------------------------------------------------------------------

@dataclass
class CallSiteFinding:
    caller_class: str
    caller_method: str
    caller_signature: str
    dex_file: str

    source_apk: str = "base.apk"

    instruction_offset: int = 0

    called_class: str = ""
    called_method: str = ""
    called_signature: str = ""

    arguments: List[str] = field(
        default_factory=list
    )

    move_result_register: Optional[str] = None

    following_instructions: List[str] = field(
        default_factory=list
    )

    conditional_branch: Optional[str] = None
    branch_offset: Optional[int] = None

    true_branch_target: str = ""
    false_branch_target: str = ""

    true_branch_effect: str = "UNKNOWN"
    false_branch_effect: str = "UNKNOWN"

    effect_summary: str = ""

    evidence_id: Optional[str] = None

    bytecode_snippet: str = ""

    # New: explicit classification of this call-site.
    #
    # "CALL_ONLY":
    #     Candidate was invoked, but the result was not traced into a branch.
    #
    # "BOOLEAN_GATE":
    #     Candidate result was captured and used in a conditional branch.
    #
    # "UNKNOWN":
    #     Insufficient information.
    verification_type: str = "UNKNOWN"

    # New: exact register path used during analysis.
    tracked_registers: List[str] = field(
        default_factory=list
    )

    # New: whether the result register was directly tested.
    result_register_tested: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "caller_class": self.caller_class,
            "caller_method": self.caller_method,
            "caller_signature": self.caller_signature,
            "dex_file": self.dex_file,
            "source_apk": self.source_apk,
            "instruction_offset": (
                f"0x{self.instruction_offset:04x}"
            ),
            "called_class": self.called_class,
            "called_method": self.called_method,
            "called_signature": self.called_signature,
            "arguments": list(
                self.arguments
            ),
            "move_result_register": self.move_result_register,
            "following_instructions": list(
                self.following_instructions
            ),
            "conditional_branch": self.conditional_branch,
            "branch_offset": (
                f"0x{self.branch_offset:04x}"
                if self.branch_offset is not None
                else None
            ),
            "true_branch_target": self.true_branch_target,
            "false_branch_target": self.false_branch_target,
            "true_branch_effect": self.true_branch_effect,
            "false_branch_effect": self.false_branch_effect,
            "effect_summary": self.effect_summary,
            "evidence_id": self.evidence_id,
            "bytecode_snippet": self.bytecode_snippet,
            "verification_type": self.verification_type,
            "tracked_registers": list(
                self.tracked_registers
            ),
            "result_register_tested": self.result_register_tested,
        }


# ---------------------------------------------------------------------------
# Boolean verification location
# ---------------------------------------------------------------------------

@dataclass
class BooleanVerificationLocation:
    dex_file: str
    source_apk: str

    class_name: str
    method_name: str
    method_signature: str

    called_boolean_method: str
    called_boolean_class: str

    instruction_offset: int

    branch_opcode: str

    result_register: str

    true_branch_target: str
    false_branch_target: str

    true_branch_effect: str = "UNKNOWN"
    false_branch_effect: str = "UNKNOWN"

    effect: str = "Conditional feature gating"

    evidence_id: Optional[str] = None

    evidence: List[str] = field(
        default_factory=list
    )

    bytecode_snippet: str = ""

    # New: explicit confidence for this location.
    confidence: Confidence = Confidence.MEDIUM

    # New: states how strongly the branch is linked to the boolean result.
    verification_type: str = "BOOLEAN_GATE"

    # New: register aliases observed while tracing.
    tracked_registers: List[str] = field(
        default_factory=list
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dex_file": self.dex_file,
            "source_apk": self.source_apk,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "method_signature": self.method_signature,
            "called_boolean_method": self.called_boolean_method,
            "called_boolean_class": self.called_boolean_class,
            "instruction_offset": (
                f"0x{self.instruction_offset:04x}"
            ),
            "branch_opcode": self.branch_opcode,
            "result_register": self.result_register,
            "true_branch_target": self.true_branch_target,
            "false_branch_target": self.false_branch_target,
            "true_branch_effect": self.true_branch_effect,
            "false_branch_effect": self.false_branch_effect,
            "effect": self.effect,
            "evidence_id": self.evidence_id,
            "evidence": list(
                self.evidence
            ),
            "bytecode_snippet": self.bytecode_snippet,
            "confidence": self.confidence.value
            if isinstance(
                self.confidence,
                Confidence,
            )
            else self.confidence,
            "verification_type": self.verification_type,
            "tracked_registers": list(
                self.tracked_registers
            ),
        }


# ---------------------------------------------------------------------------
# Constructor findings
# ---------------------------------------------------------------------------

@dataclass
class ConstructorFinding:
    dex_file: str
    class_name: str
    constructor_signature: str

    verification: str
    network_interaction: str

    source_apk: str = "base.apk"

    initializes_billing_client: bool = False
    sets_premium_flags: bool = False
    reads_local_state: bool = False
    loads_remote_config: bool = False

    called_methods: List[str] = field(
        default_factory=list
    )

    evidence: List[str] = field(
        default_factory=list
    )

    boolean_field_initialized: str = ""

    evidence_id: Optional[str] = None

    snippet: Optional[str] = None


# ---------------------------------------------------------------------------
# Network endpoint
# ---------------------------------------------------------------------------

@dataclass
class NetworkEndpoint:
    url: str
    domain: str

    http_method: Optional[str] = None

    client_library: str = ""

    referenced_from_class: str = ""
    referenced_from_method: str = ""

    dex_file: str = ""

    source_apk: str = "base.apk"

    is_purchase_related: bool = False

    relevance_level: str = "LOW"

    relevance_reason: str = ""

    evidence_id: Optional[str] = None

    # New optional correlation information.
    evidence: List[str] = field(
        default_factory=list
    )

    # New: all known source methods for this URL.
    # This is optional so old consumers remain compatible.
    locations: List[Dict[str, str]] = field(
        default_factory=list
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "http_method": self.http_method,
            "client_library": self.client_library,
            "referenced_from_class": self.referenced_from_class,
            "referenced_from_method": self.referenced_from_method,
            "dex_file": self.dex_file,
            "source_apk": self.source_apk,
            "is_purchase_related": self.is_purchase_related,
            "relevance_level": self.relevance_level,
            "relevance_reason": self.relevance_reason,
            "evidence_id": self.evidence_id,
            "evidence": list(
                self.evidence
            ),
            "locations": list(
                self.locations
            ),
        }


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------

@dataclass
class CallGraphNode:
    id: str
    label: str
    type: str

    dex_file: Optional[str] = None
    source_apk: Optional[str] = None

    details: Dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class CallGraphEdge:
    source: str
    target: str
    label: str = ""


@dataclass
class CallGraphData:
    nodes: List[CallGraphNode] = field(
        default_factory=list
    )

    edges: List[CallGraphEdge] = field(
        default_factory=list
    )

    sample_flow_path: List[str] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Control-flow graph
# ---------------------------------------------------------------------------

@dataclass
class CFGBlock:
    id: str
    start_offset: int
    end_offset: int

    instructions: List[str] = field(
        default_factory=list
    )

    successors: List[str] = field(
        default_factory=list
    )

    predecessors: List[str] = field(
        default_factory=list
    )

    true_edge: Optional[str] = None
    false_edge: Optional[str] = None

    is_entry: bool = False
    is_exit: bool = False


@dataclass
class MethodCFG:
    method_signature: str
    class_name: str
    dex_file: str

    blocks: List[CFGBlock] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------

@dataclass
class BillingFinding:
    providers_detected: List[str] = field(
        default_factory=list
    )

    features_detected: List[str] = field(
        default_factory=list
    )

    billing_classes: List[str] = field(
        default_factory=list
    )

    billing_methods: List[str] = field(
        default_factory=list
    )

    has_play_billing: bool = False
    has_google_play: bool = False
    has_aidl: bool = False
    has_revenuecat: bool = False
    has_qonversion: bool = False
    has_adapty: bool = False
    has_stripe: bool = False
    has_paypal: bool = False
    has_webview_payment: bool = False

    has_custom: bool = False
    has_custom_billing: bool = False

    google_play_version: Optional[str] = None

    evidence: List[str] = field(
        default_factory=list
    )

    confidence: Confidence = Confidence.LOW

    evidence_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "providers_detected": list(
                self.providers_detected
            ),
            "features_detected": list(
                self.features_detected
            ),
            "billing_classes": list(
                self.billing_classes
            ),
            "billing_methods": list(
                self.billing_methods
            ),
            "has_play_billing": self.has_play_billing,
            "has_google_play": self.has_google_play,
            "has_aidl": self.has_aidl,
            "has_revenuecat": self.has_revenuecat,
            "has_qonversion": self.has_qonversion,
            "has_adapty": self.has_adapty,
            "has_stripe": self.has_stripe,
            "has_paypal": self.has_paypal,
            "has_webview_payment": self.has_webview_payment,
            "has_custom": self.has_custom,
            "has_custom_billing": self.has_custom_billing,
            "google_play_version": self.google_play_version,
            "evidence": list(
                self.evidence
            ),
            "confidence": self.confidence.value
            if isinstance(
                self.confidence,
                Confidence,
            )
            else self.confidence,
            "evidence_id": self.evidence_id,
        }


# ---------------------------------------------------------------------------
# Class-level analysis
# ---------------------------------------------------------------------------

@dataclass
class ClassLevelAnalysis:
    primary_purchase_class: Optional[str] = None
    primary_premium_class: Optional[str] = None

    primary_boolean_method: Optional[str] = None
    primary_boolean_dex: Optional[str] = None
    primary_boolean_signature: Optional[str] = None

    confidence: Confidence = Confidence.LOW

    evidence: List[str] = field(
        default_factory=list
    )

    top_purchase_classes: List[str] = field(
        default_factory=list
    )

    top_premium_classes: List[str] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Architecture classification
# ---------------------------------------------------------------------------

@dataclass
class ClassificationFinding:
    classification: ClassificationType = (
        ClassificationType.UNKNOWN
    )

    confidence: Confidence = Confidence.LOW

    reasons: List[str] = field(
        default_factory=list
    )

    server_side_evidence: List[str] = field(
        default_factory=list
    )

    client_side_evidence: List[str] = field(
        default_factory=list
    )

    evidence_id: Optional[str] = None


# ---------------------------------------------------------------------------
# APK metadata
# ---------------------------------------------------------------------------

@dataclass
class ApkInfo:
    file_name: str
    file_size_bytes: int

    package_name: str

    app_label: str = ""

    version_name: str = ""
    version_code: str = ""

    min_sdk: str = ""
    target_sdk: str = ""
    compile_sdk: str = ""

    input_type: str = "APK"

    container_name: str = ""

    contained_apks: List[Dict[str, Any]] = field(
        default_factory=list
    )

    permissions: List[str] = field(
        default_factory=list
    )

    activities: List[str] = field(
        default_factory=list
    )

    services: List[str] = field(
        default_factory=list
    )

    receivers: List[str] = field(
        default_factory=list
    )

    providers: List[str] = field(
        default_factory=list
    )

    native_libraries: List[str] = field(
        default_factory=list
    )

    assets: List[str] = field(
        default_factory=list
    )

    signing_info: Dict[str, Any] = field(
        default_factory=dict
    )

    dex_files_info: List[Dict[str, Any]] = field(
        default_factory=list
    )

    total_dex_count: int = 0


# ---------------------------------------------------------------------------
# AI reasoning
# ---------------------------------------------------------------------------

@dataclass
class AIReasoningFinding:
    purchase_logic_exists: str = "UNKNOWN"
    architecture: str = "UNKNOWN"

    confidence: str = "LOW"

    primary_boolean_method_info: Dict[str, Any] = field(
        default_factory=dict
    )

    boolean_verification_location_info: Dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    constructor_premium_check: str = "UNKNOWN"

    constructor_evidence: List[str] = field(
        default_factory=list
    )

    cited_evidence_ids: List[str] = field(
        default_factory=list
    )

    architecture_summary: str = ""
    purchase_flow_explanation: str = ""
    boolean_gate_explanation: str = ""
    security_assessment: str = ""

    reasoning_chain: List[str] = field(
        default_factory=list
    )

    has_discrepancy: bool = False
    discrepancy_details: str = ""

    is_ai_generated: bool = False

    raw_response: Optional[str] = None


# ---------------------------------------------------------------------------
# Top-level analysis report
# ---------------------------------------------------------------------------

@dataclass
class AnalysisReport:
    analysis_timestamp: str = ""

    apk_info: Optional[ApkInfo] = None

    input_type: str = "APK"

    container_name: str = ""

    contained_apks: List[Dict[str, Any]] = field(
        default_factory=list
    )

    apk: Dict[str, Any] = field(
        default_factory=dict
    )

    dex_files: List[DexFileInfo] = field(
        default_factory=list
    )

    obfuscation: Optional[
        ObfuscationAnalysis
    ] = None

    billing: Optional[
        BillingFinding
    ] = None

    classification: Optional[
        ClassificationFinding
    ] = None

    class_analysis: Optional[
        ClassLevelAnalysis
    ] = None

    boolean_candidates: List[
        BooleanMethodCandidate
    ] = field(
        default_factory=list
    )

    boolean_verification_locations: List[
        BooleanVerificationLocation
    ] = field(
        default_factory=list
    )

    call_sites: List[
        CallSiteFinding
    ] = field(
        default_factory=list
    )

    constructors: List[
        ConstructorFinding
    ] = field(
        default_factory=list
    )

    network_endpoints: List[
        NetworkEndpoint
    ] = field(
        default_factory=list
    )

    evidence_inventory: List[
        EvidenceItem
    ] = field(
        default_factory=list
    )

    cfgs: List[
        MethodCFG
    ] = field(
        default_factory=list
    )

    ai_reasoning: Optional[
        AIReasoningFinding
    ] = None

    analysis_status: str = "COMPLETED"

    analysis_quality: str = "FULL"

    unsupported_opcodes_detected: List[
        Dict[str, Any]
    ] = field(
        default_factory=list
    )

    warnings_or_errors: List[str] = field(
        default_factory=list
    )

    limitations: List[str] = field(
        default_factory=list
    )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert report to JSON-safe dictionary.

        asdict() recursively handles dataclasses, but Enum values need
        normalization because plain json.dumps() cannot serialize Enum
        instances in every Python version/configuration.
        """

        data = asdict(
            self
        )

        return self._json_safe(
            data
        )

    @classmethod
    def _json_safe(
        cls,
        value: Any,
    ) -> Any:
        """Recursively convert enums/dataclasses/collections to JSON-safe data."""

        if isinstance(
            value,
            Enum,
        ):
            return value.value

        if isinstance(
            value,
            dict,
        ):
            return {
                str(key): cls._json_safe(
                    item
                )
                for key, item in value.items()
            }

        if isinstance(
            value,
            (list, tuple, set),
        ):
            return [
                cls._json_safe(
                    item
                )
                for item in value
            ]

        return value
