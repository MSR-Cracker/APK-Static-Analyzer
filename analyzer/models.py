"""Data models for APK Static Analyzer."""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ClassificationType(str, Enum):
    SERVER_SIDE = "SERVER_SIDE"
    CLIENT_SIDE = "CLIENT_SIDE"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"


class StatusState(str, Enum):
    CONFIRMED = "Confirmed"
    STRONG_CANDIDATE = "Strong candidate"
    POSSIBLE = "Possible"
    NOT_FOUND = "Not found"


@dataclass
class DexMethod:
    dex_file: str
    class_name: str
    package: str
    method_name: str
    signature: str
    return_type: str
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
    types_referenced: List[str] = field(default_factory=list)
    bytecode_snippet: Optional[str] = None


@dataclass
class BooleanMethodCandidate:
    dex_file: str
    class_name: str
    package: str
    method_name: str
    signature: str
    return_type: str  # 'boolean' or 'Z'
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


@dataclass
class ConstructorFinding:
    dex_file: str
    class_name: str
    constructor_signature: str
    verification: str  # YES / NO / UNKNOWN
    network_interaction: str  # YES / NO / UNKNOWN
    initializes_billing_client: bool = False
    sets_premium_flags: bool = False
    reads_local_state: bool = False
    loads_remote_config: bool = False
    called_methods: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
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
    is_purchase_related: bool = False
    relevance_reason: str = ""


@dataclass
class CallGraphNode:
    id: str
    label: str
    type: str  # 'entrypoint', 'activity', 'billing', 'boolean_check', 'verification', 'network'
    dex_file: Optional[str] = None
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
class BillingFinding:
    providers_detected: List[str] = field(default_factory=list)
    features_detected: List[str] = field(default_factory=list)
    billing_classes: List[str] = field(default_factory=list)
    billing_methods: List[str] = field(default_factory=list)
    has_play_billing: bool = False
    has_revenuecat: bool = False
    has_stripe: bool = False
    has_paypal: bool = False
    has_webview_payment: bool = False
    has_custom_billing: bool = False
    evidence: List[str] = field(default_factory=list)


@dataclass
class ClassificationFinding:
    classification: ClassificationType = ClassificationType.UNKNOWN
    confidence: Confidence = Confidence.LOW
    reasons: List[str] = field(default_factory=list)
    server_side_evidence: List[str] = field(default_factory=list)
    client_side_evidence: List[str] = field(default_factory=list)


@dataclass
class ApkInfo:
    file_name: str
    file_size_bytes: int
    package_name: str
    version_name: str
    version_code: str
    min_sdk: str
    target_sdk: str
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
class GeminiInterpretation:
    summary: str = ""
    payment_architecture: str = ""
    strongest_boolean_candidate: Optional[Dict[str, Any]] = None
    classification_explanation: str = ""
    discrepancies: List[str] = field(default_factory=list)
    confidence: str = "Medium"
    raw_model_response: Optional[str] = None


@dataclass
class AnalysisReport:
    apk: Dict[str, Any] = field(default_factory=dict)
    dex_files: List[Dict[str, Any]] = field(default_factory=list)
    billing: Dict[str, Any] = field(default_factory=dict)
    purchase_boolean_methods: List[Dict[str, Any]] = field(default_factory=list)
    constructors: List[Dict[str, Any]] = field(default_factory=list)
    network: Dict[str, Any] = field(default_factory=dict)
    call_graph: Dict[str, Any] = field(default_factory=dict)
    classification: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    analysis_status: str = "COMPLETED"  # or "PARTIAL_ANALYSIS"
    warnings_or_errors: List[str] = field(default_factory=list)
    gemini_interpretation: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
