"""Gemini AI interpretation module: analyzes analysis.json findings without hallucinating non-existent classes/methods."""
import os
import json
import logging
from typing import Dict, Any, Optional
from analyzer.models import GeminiInterpretation

logger = logging.getLogger(__name__)


class GeminiInterpreter:
    """Uses Google Gemini API to interpret technical static analysis facts in analysis.json."""

    SYSTEM_INSTRUCTION = (
        "You are a specialized Android Reverse Engineering & In-App Billing Security Expert. "
        "Your task is to interpret the provided static analysis JSON of an Android APK. "
        "CRITICAL RULES:\n"
        "1. Strictly ground your analysis in the provided technical facts in analysis.json.\n"
        "2. NEVER invent, hallucinate, or assume any class name, method signature, DEX file, URL, or API endpoint that is not in the JSON.\n"
        "3. Focus on explaining how the app verifies purchases, which boolean method is the primary entitlement gate, and the security posture (Server-side vs Client-side).\n"
        "4. Format your output as a clean JSON object."
    )

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")

    def interpret(self, analysis_data: Dict[str, Any]) -> Optional[GeminiInterpretation]:
        if not self.api_key:
            logger.info("GEMINI_API_KEY is not configured. Skipping AI interpretation.")
            return None

        # Build prompt from static analysis facts
        prompt = (
            "Analyze the following Android APK static analysis data and provide expert synthesis:\n\n"
            f"```json\n{json.dumps(analysis_data, indent=2)[:30000]}\n```\n\n"
            "Respond strictly in valid JSON with these exact keys:\n"
            "{\n"
            '  "summary": "Concise Arabic and English executive summary of the billing implementation",\n'
            '  "payment_architecture": "Explanation of payment flows and verification flow",\n'
            '  "strongest_boolean_candidate": {"dex": "...", "class": "...", "method": "...", "reason": "..."},\n'
            '  "classification_explanation": "Detailed rationale for SERVER_SIDE / CLIENT_SIDE / MIXED / UNKNOWN",\n'
            '  "discrepancies": ["List of any potential issues, obfuscation traits, or bypass risks"],\n'
            '  "confidence": "High / Medium / Low"\n'
            "}"
        )

        try:
            # Check if google-genai or google.generativeai or urllib can be used
            try:
                from google import genai
                from google.genai import types
                client = genai.Client(api_key=self.api_key)
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=self.SYSTEM_INSTRUCTION,
                        response_mime_type="application/json",
                    )
                )
                text = response.text or "{}"
            except ImportError:
                # Fallback to direct HTTP request using urllib
                import urllib.request
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}"
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "systemInstruction": {"parts": [{"text": self.SYSTEM_INSTRUCTION}]},
                    "generationConfig": {"responseMimeType": "application/json"}
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    text = res_json["candidates"][0]["content"]["parts"][0]["text"]

            parsed = json.loads(text)
            return GeminiInterpretation(
                summary=parsed.get("summary", ""),
                payment_architecture=parsed.get("payment_architecture", ""),
                strongest_boolean_candidate=parsed.get("strongest_boolean_candidate"),
                classification_explanation=parsed.get("classification_explanation", ""),
                discrepancies=parsed.get("discrepancies", []),
                confidence=parsed.get("confidence", "Medium"),
                raw_model_response=text,
            )

        except Exception as e:
            logger.warning(f"Failed to run Gemini AI interpretation: {e}")
            return GeminiInterpretation(
                summary="AI Interpretation skipped due to request error or invalid key.",
                payment_architecture="See static analysis facts above.",
                classification_explanation=str(e),
                confidence="Low"
            )
