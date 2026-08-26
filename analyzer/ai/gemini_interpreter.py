"""Gemini AI Interpreter: Performs grounded, evidence-based reasoning over the static analysis findings."""
import os
import json
import logging
from typing import Dict, Any, Optional, List
from analyzer.models import AnalysisReport, AIReasoningFinding, ClassificationType

logger = logging.getLogger(__name__)


class GeminiInterpreter:
    """Interprets static analysis results using Google Gemini AI, strictly grounding all deductions in numbered Evidence IDs."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.client = None

        if self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize GenAI client: {e}")

    def interpret(self, report: AnalysisReport, evidence_package: Dict[str, Any]) -> AIReasoningFinding:
        """Runs grounded AI reasoning using Gemini 2.5 Flash."""
        if not self.client:
            return self._generate_fallback_reasoning(report)

        system_instruction = (
            "You are an expert Android Security & Static Analysis AI. "
            "You will be given a JSON-formatted Evidence Package containing verified facts from an Android APK / APKS container. "
            "STRICT RULES:\n"
            "1. Ground every claim in the provided Evidence IDs (e.g., E001, E002, etc.).\n"
            "2. DO NOT invent or hallucinate classes, methods, signatures, endpoints, or branches not present in the evidence.\n"
            "3. Answer the key assessment questions:\n"
            "   a) Does purchase / premium logic exist? (YES / NO / UNKNOWN)\n"
            "   b) Architecture classification: (SERVER_SIDE / CLIENT_SIDE / MIXED / UNKNOWN)\n"
            "   c) Primary Purchase Boolean method\n"
            "   d) Where is it verified (caller, branch, taken vs fallthrough path)?\n"
            "   e) Constructor premium verification (YES / NO / UNKNOWN)?\n"
            "4. If your reasoning disagrees with the static analysis classification, explain the discrepancy.\n"
            "5. Output valid JSON matching the schema."
        )

        prompt_text = (
            f"Analyze this static evidence package and provide your grounded assessment:\n"
            f"{json.dumps(evidence_package, indent=2)}"
        )

        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt_text,
                config={
                    "system_instruction": system_instruction,
                    "response_mime_type": "application/json",
                    "response_schema": {
                        "type": "OBJECT",
                        "properties": {
                            "purchase_logic_exists": {"type": "STRING", "enum": ["YES", "NO", "UNKNOWN"]},
                            "architecture": {"type": "STRING", "enum": ["SERVER_SIDE", "CLIENT_SIDE", "MIXED", "UNKNOWN"]},
                            "confidence": {"type": "STRING", "enum": ["HIGH", "MEDIUM", "LOW"]},
                            "primary_boolean_method_info": {
                                "type": "OBJECT",
                                "properties": {
                                    "dex": {"type": "STRING"},
                                    "class": {"type": "STRING"},
                                    "method": {"type": "STRING"},
                                    "signature": {"type": "STRING"},
                                    "return_type": {"type": "STRING"},
                                    "confidence": {"type": "STRING"}
                                }
                            },
                            "boolean_verification_location_info": {
                                "type": "OBJECT",
                                "properties": {
                                    "caller_class": {"type": "STRING"},
                                    "caller_method": {"type": "STRING"},
                                    "instruction_offset": {"type": "STRING"},
                                    "branch_opcode": {"type": "STRING"},
                                    "true_path": {"type": "STRING"},
                                    "false_path": {"type": "STRING"}
                                }
                            },
                            "constructor_premium_check": {"type": "STRING", "enum": ["YES", "NO", "UNKNOWN"]},
                            "constructor_evidence": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            },
                            "cited_evidence_ids": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            },
                            "architecture_summary": {"type": "STRING"},
                            "purchase_flow_explanation": {"type": "STRING"},
                            "boolean_gate_explanation": {"type": "STRING"},
                            "security_assessment": {"type": "STRING"},
                            "reasoning_chain": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            },
                            "has_discrepancy": {"type": "BOOLEAN"},
                            "discrepancy_details": {"type": "STRING"}
                        },
                        "required": [
                            "purchase_logic_exists",
                            "architecture",
                            "confidence",
                            "architecture_summary",
                            "purchase_flow_explanation",
                            "boolean_gate_explanation",
                            "security_assessment",
                            "reasoning_chain",
                            "cited_evidence_ids"
                        ]
                    }
                }
            )

            data = json.loads(response.text)
            
            # Check discrepancy with static analysis
            static_arch = report.classification.classification.value if report.classification else "UNKNOWN"
            ai_arch = data.get("architecture", static_arch)
            has_disc = data.get("has_discrepancy", False) or (static_arch != "UNKNOWN" and ai_arch != static_arch)
            disc_details = data.get("discrepancy_details", "")
            if has_disc and not disc_details:
                disc_details = f"Static analysis classified as '{static_arch}', while AI reasoning evaluated as '{ai_arch}'."

            return AIReasoningFinding(
                purchase_logic_exists=data.get("purchase_logic_exists", "YES"),
                architecture=ai_arch,
                confidence=data.get("confidence", "HIGH"),
                primary_boolean_method_info=data.get("primary_boolean_method_info", {}),
                boolean_verification_location_info=data.get("boolean_verification_location_info", {}),
                constructor_premium_check=data.get("constructor_premium_check", "NO"),
                constructor_evidence=data.get("constructor_evidence", []),
                cited_evidence_ids=data.get("cited_evidence_ids", []),
                architecture_summary=data.get("architecture_summary", ""),
                purchase_flow_explanation=data.get("purchase_flow_explanation", ""),
                boolean_gate_explanation=data.get("boolean_gate_explanation", ""),
                security_assessment=data.get("security_assessment", ""),
                reasoning_chain=data.get("reasoning_chain", []),
                has_discrepancy=has_disc,
                discrepancy_details=disc_details,
                is_ai_generated=True,
                raw_response=response.text,
            )
        except Exception as e:
            logger.error(f"Gemini API inference error: {e}")
            return self._generate_fallback_reasoning(report)

    def _generate_fallback_reasoning(self, report: AnalysisReport) -> AIReasoningFinding:
        """Deterministic grounded reasoning fallback if Gemini API is unavailable or offline."""
        arch = report.classification.classification.value if report.classification else "UNKNOWN"
        cls_name = report.class_analysis.primary_purchase_class if report.class_analysis else "Identified Billing Class"
        bool_m = report.class_analysis.primary_boolean_method if report.class_analysis else "Primary Boolean Gate"
        bool_dex = report.class_analysis.primary_boolean_dex if report.class_analysis else "classes.dex"
        bool_sig = report.class_analysis.primary_boolean_signature if report.class_analysis else "()Z"

        has_billing = bool(report.billing and report.billing.providers_detected)
        has_boolean = bool(report.boolean_candidates)
        purchase_exists = "YES" if (has_billing or has_boolean) else "UNKNOWN"

        top_verif = report.boolean_verification_locations[0] if report.boolean_verification_locations else None
        top_ctor = report.constructors[0] if report.constructors else None

        cited_ids = [e.id for e in report.evidence_inventory[:8]]

        summary = (
            f"The application implements a {arch} monetization model based on static Dalvik DEX disassembly. "
            f"Billing operations are coordinated through '{cls_name}', with feature gating controlled by '{bool_m}'."
        )

        flow = (
            f"1. User initiates a purchase or app checks existing entitlements via '{cls_name}'.\n"
            f"2. Billing state or purchase token is queried through registered providers: {', '.join(report.billing.providers_detected if report.billing else ['None'])}.\n"
            f"3. Premium entitlement state is evaluated and returned via '{bool_m}'."
        )

        gate = (
            f"Feature access is gated through boolean validation routines. "
            + (f"Verification location identified in '{top_verif.class_name}->{top_verif.method_name}' using opcode '{top_verif.branch_opcode}' at offset 0x{top_verif.instruction_offset:04x}." if top_verif else "No direct branch verification call sites mapped.")
        )

        security = (
            "Local client-side boolean checks can be bypassed by method hooking (Frida/Xposed) or DEX binary patching if not validated by a secure backend server."
            if arch in ("CLIENT_SIDE", "MIXED")
            else "Server-authoritative token validation protects premium endpoints against purely client-side binary modification."
        )

        chain = [
            f"Identified {len(report.dex_files)} DEX files across split/base APK containers.",
            f"Discovered {len(report.billing.providers_detected if report.billing else [])} billing provider SDK integrations ({', '.join(report.billing.providers_detected if report.billing else ['None'])}).",
            f"Mapped {len(report.boolean_candidates)} boolean entitlement candidates, with top candidate '{bool_m}'.",
            f"Located {len(report.boolean_verification_locations)} conditional branch gating sites.",
            f"Constructor premium check assessed as: '{top_ctor.verification if top_ctor else 'NO'}'.",
            f"Concluded {arch} architecture with grounded evidence.",
        ]

        return AIReasoningFinding(
            purchase_logic_exists=purchase_exists,
            architecture=arch,
            confidence=report.classification.confidence.value if report.classification else "MEDIUM",
            primary_boolean_method_info={
                "dex": bool_dex,
                "class": cls_name,
                "method": bool_m,
                "signature": bool_sig,
                "return_type": "boolean",
                "confidence": "HIGH" if has_boolean else "LOW",
            },
            boolean_verification_location_info={
                "caller_class": top_verif.class_name if top_verif else "None",
                "caller_method": top_verif.method_name if top_verif else "None",
                "instruction_offset": f"0x{top_verif.instruction_offset:04x}" if top_verif else "N/A",
                "branch_opcode": top_verif.branch_opcode if top_verif else "N/A",
                "true_path": top_verif.true_branch_target if top_verif else "N/A",
                "false_path": top_verif.false_branch_target if top_verif else "N/A",
            },
            constructor_premium_check=top_ctor.verification if top_ctor else "NO",
            constructor_evidence=top_ctor.evidence if top_ctor else ["No verification found in class constructors"],
            cited_evidence_ids=cited_ids,
            architecture_summary=summary,
            purchase_flow_explanation=flow,
            boolean_gate_explanation=gate,
            security_assessment=security,
            reasoning_chain=chain,
            has_discrepancy=False,
            discrepancy_details="",
            is_ai_generated=False,
        )
