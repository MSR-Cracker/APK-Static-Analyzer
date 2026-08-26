"""Data models for APK and APKS Static Analyzer."""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Union
from enum import Enum


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


@dataclass
class EvidenceItem:
    id: str  # e.g. "E001", "E002"
    category: str  # "BILLING_SDK", "BOOLEAN_METHOD", "VERIFICATION_CALL_SITE", "BRANCH_EFFECT", "CONSTRUCTOR_CHECK", "NETWORK_ENDPOINT", "LOCAL_PERSISTENCE", "OBFUSCATION"
    summary: str
    description: str
    confidence: Confidence = Confidence.HIGH
    dex_file: Optional[str] = None
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    offset: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContainedApkInfo:
    name: str
    file_size_bytes: int = 0
    dex_count: int = 0
    is_base: bool = False
    split_type: str = "base"  # 'base', 'config_abi', 'config_density', 'config_lang', 'feature'
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    permissions: List[str] = field(default_factory=list)


@dataclass
class DexFileInfo:
    name: str
    source_apk: str = "base.apk"
    size_bytes: int = 0
    class_count: int = 0
    method_count: int = 0
    unsupported_opcodes_count: int = 0
    analysis_quality: str = "FULL"  # "FULL" or "PARTIAL"


@dataclass
class InstructionDetail:
    offset: int
    opcode: int
    opcode_name: str
    raw_hex: str
    operands: str
    registers: List[str] = field(default_factory=list)
    branch_target: Optional[int] = None
    referenced_method: Optional[str] = None
    referenced_field: Optional[str] = None
    referenced_string: Optional[str] = None
    referenced_type: Optional[str] = None
    comment: str = ""


@dataclass
class DexMethod:
    dex_file: str
    class_name: str
    package: str
    method_name: str
    signature: str
    return_type: str
    source_apk: str = "base.apk"
    parameters: List[str] = field(default_factory=list)
    access_flags: List[str] = field(default_factory=list)
    is_static: bool = False
    is_native: bool = False
    is_abstract: bool = False
    is_constructor: bool = False
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    strings_referenced: List[str] = field(default_factory=list)
    fields_referenced: List[str] = field(default_factory=list)
    types_referenced: List[str] = field(default_factory=list)
    branches: List[Dict[str, Any]] = field(default_factory=list)
    returns: List[Dict[str, Any]] = field(default_factory=list)
    bytecode_snippet: Optional[str] = None
    decompiled_source: Optional[str] = None
    instructions: List[InstructionDetail] = field(default_factory=list)
    unsupported_opcodes: List[Dict[str, Any]] = field(default_factory=list)
    analysis_quality: str = "FULL"  # "FULL" or "PARTIAL"

    def to_dict(self) -> Dict[str, Any]:
        """Unified method representation strictly matching the specification."""
        return {
            "dex": self.dex_file,
            "class": self.class_name,
            "method": self.method_name,
            "signature": self.signature,
            "return_type": self.return_type,
            "access": self.access_flags,
            "instructions": [
                {
                    "offset": f"0x{i.offset:04x}",
                    "opcode": i.opcode_name,
                    "operands": i.operands,
                    "registers": i.registers,
                    "comment": i.comment,
                }
                for i in self.instructions
            ],
            "called_methods": self.callees,
            "referenced_fields": self.fields_referenced,
            "strings": self.strings_referenced,
            "branches": self.branches,
            "returns": self.returns,
            "analysis_quality": self.analysis_quality,
        }


@dataclass
class ObfuscationAnalysis:
    status: ObfuscationStatus = ObfuscationStatus.NO
    confidence: Confidence = Confidence.LOW
    evidence: List[str] = field(default_factory=list)
    short_class_ratio: float = 0.0
    short_method_ratio: float = 0.0
    short_package_ratio: float = 0.0
    missing_debug_info_ratio: float = 0.0
    proguard_r8_patterns: List[str] = field(default_factory=list)


@dataclass
class BooleanMethodCandidate:
    dex_file: str
    class_name: str
    package: str
    method_name: str
    signature: str
    return_type: str  # 'boolean' or 'Z'
    source_apk: str = "base.apk"
    parameters: List[str] = field(default_factory=list)
    access_flags: List[str] = field(default_factory=list)
    is_static: bool = False
    is_native: bool = False
    is_abstract: bool = False
    is_constructor: bool = False
    source_location: str = ""
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    status: StatusState = StatusState.POSSIBLE
    purchase_relevance_evidence: List[str] = field(default_factory=list)
    score: float = 0.0
    decompiled_snippet: Optional[str] = None
    why_identified: str = ""
    evidence_id: Optional[str] = None
    analysis_quality: str = "FULL"


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
    arguments: List[str] = field(default_factory=list)
    move_result_register: Optional[str] = None
    following_instructions: List[str] = field(default_factory=list)
    conditional_branch: Optional[str] = None
    branch_offset: Optional[int] = None
    true_branch_target: str = ""
    false_branch_target: str = ""
    true_branch_effect: str = "UNKNOWN"
    false_branch_effect: str = "UNKNOWN"
    effect_summary: str = ""
    evidence_id: Optional[str] = None
    bytecode_snippet: str = ""


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
    branch_opcode: str  # e.g. 'if-eqz', 'if-nez'
    result_register: str  # e.g. 'v0', 'v1'
    true_branch_target: str
    false_branch_target: str
    true_branch_effect: str = "UNKNOWN"
    false_branch_effect: str = "UNKNOWN"
    effect: str = "Conditional feature gating"
    evidence_id: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    bytecode_snippet: str = ""


@dataclass
class ConstructorFinding:
    dex_file: str
    class_name: str
    constructor_signature: str
    verification: str  # YES / NO / UNKNOWN
    network_interaction: str  # YES / NO / UNKNOWN
    source_apk: str = "base.apk"
    initializes_billing_client: bool = False
    sets_premium_flags: bool = False
    reads_local_state: bool = False
    loads_remote_config: bool = False
    called_methods: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    boolean_field_initialized: str = ""
    evidence_id: Optional[str] = None
    snippet: Optional[str] = None


@dataclass
class NetworkEndpoint:
    url: str
    domain: str
    http_method: Optional[str] = None
    client_library: str = ""  # Retrofit, OkHttp, Volley, WebView, HttpURLConnection
    referenced_from_class: str = ""
    referenced_from_method: str = ""
    dex_file: str = ""
    source_apk: str = "base.apk"
    is_purchase_related: bool = False
    relevance_level: str = "LOW"  # HIGH, MEDIUM, LOW, NONE
    relevance_reason: str = ""
    evidence_id: Optional[str] = None


@dataclass
class CallGraphNode:
    id: str
    label: str
    type: str  # 'entrypoint', 'activity', 'billing', 'boolean_check', 'verification', 'network'
    dex_file: Optional[str] = None
    source_apk: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CallGraphEdge:
    source: str
    target: str
    label: str = ""


@dataclass
class CallGraphData:
    nodes: List[CallGraphNode] = field(default_factory=list)
    edges: List[CallGraphEdge] = field(default_factory=list)
    sample_flow_path: List[str] = field(default_factory=list)


@dataclass
class CFGBlock:
    id: str
    start_offset: int
    end_offset: int
    instructions: List[str] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)
    true_edge: Optional[str] = None
    false_edge: Optional[str] = None
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class MethodCFG:
    method_signature: str
    class_name: str
    dex_file: str
    blocks: List[CFGBlock] = field(default_factory=list)


@dataclass
class BillingFinding:
    providers_detected: List[str] = field(default_factory=list)
    features_detected: List[str] = field(default_factory=list)
    billing_classes: List[str] = field(default_factory=list)
    billing_methods: List[str] = field(default_factory=list)
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
    evidence: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    evidence_id: Optional[str] = None


@dataclass
class ClassLevelAnalysis:
    primary_purchase_class: Optional[str] = None
    primary_premium_class: Optional[str] = None
    primary_boolean_method: Optional[str] = None
    primary_boolean_dex: Optional[str] = None
    primary_boolean_signature: Optional[str] = None
    confidence: Confidence = Confidence.LOW
    evidence: List[str] = field(default_factory=list)
    top_purchase_classes: List[str] = field(default_factory=list)
    top_premium_classes: List[str] = field(default_factory=list)


@dataclass
class ClassificationFinding:
    classification: ClassificationType = ClassificationType.UNKNOWN
    confidence: Confidence = Confidence.LOW
    reasons: List[str] = field(default_factory=list)
    server_side_evidence: List[str] = field(default_factory=list)
    client_side_evidence: List[str] = field(default_factory=list)
    evidence_id: Optional[str] = None


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
    input_type: str = "APK"  # 'APK' or 'APKS'
    container_name: str = ""
    contained_apks: List[Dict[str, Any]] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    native_libraries: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    signing_info: Dict[str, Any] = field(default_factory=dict)
    dex_files_info: List[Dict[str, Any]] = field(default_factory=list)
    total_dex_count: int = 0


@dataclass
class AIReasoningFinding:
    purchase_logic_exists: str = "UNKNOWN"  # YES / NO / UNKNOWN
    architecture: str = "UNKNOWN"  # SERVER_SIDE / CLIENT_SIDE / MIXED / UNKNOWN
    confidence: str = "LOW"
    primary_boolean_method_info: Dict[str, Any] = field(default_factory=dict)
    boolean_verification_location_info: Dict[str, Any] = field(default_factory=dict)
    constructor_premium_check: str = "UNKNOWN"  # YES / NO / UNKNOWN
    constructor_evidence: List[str] = field(default_factory=list)
    cited_evidence_ids: List[str] = field(default_factory=list)
    architecture_summary: str = ""
    purchase_flow_explanation: str = ""
    boolean_gate_explanation: str = ""
    security_assessment: str = ""
    reasoning_chain: List[str] = field(default_factory=list)
    has_discrepancy: bool = False
    discrepancy_details: str = ""
    is_ai_generated: bool = False
    raw_response: Optional[str] = None


@dataclass
class AnalysisReport:
    analysis_timestamp: str = ""
    apk_info: Optional[ApkInfo] = None
    input_type: str = "APK"
    container_name: str = ""
    contained_apks: List[Dict[str, Any]] = field(default_factory=list)
    apk: Dict[str, Any] = field(default_factory=dict)
    dex_files: List[DexFileInfo] = field(default_factory=list)
    obfuscation: Optional[ObfuscationAnalysis] = None
    billing: Optional[BillingFinding] = None
    classification: Optional[ClassificationFinding] = None
    class_analysis: Optional[ClassLevelAnalysis] = None
    boolean_candidates: List[BooleanMethodCandidate] = field(default_factory=list)
    boolean_verification_locations: List[BooleanVerificationLocation] = field(default_factory=list)
    call_sites: List[CallSiteFinding] = field(default_factory=list)
    constructors: List[ConstructorFinding] = field(default_factory=list)
    network_endpoints: List[NetworkEndpoint] = field(default_factory=list)
    evidence_inventory: List[EvidenceItem] = field(default_factory=list)
    cfgs: List[MethodCFG] = field(default_factory=list)
    ai_reasoning: Optional[AIReasoningFinding] = None
    analysis_status: str = "COMPLETED"
    analysis_quality: str = "FULL"  # "FULL" or "PARTIAL"
    unsupported_opcodes_detected: List[Dict[str, Any]] = field(default_factory=list)
    warnings_or_errors: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
