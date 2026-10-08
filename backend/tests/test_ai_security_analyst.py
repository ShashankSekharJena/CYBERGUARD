"""
CYBERGUARD AI Security Analyst Integration Tests

Verifies AI Security Analyst functionality and deterministic fallback behavior:
1. AI service with mocked successful response
2. Missing API key fallback
3. API failure fallback
4. Incident not found (404)
5. Valid AI response structure & endpoint
6. Malformed AI response handling
7. AI chat endpoint (grounded answers & unsupported evidence response)
"""

import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.ai_security_analyst import (
    analyze_incident,
    ask_incident_question,
    generate_fallback_analysis,
    extract_json_from_llm_text
)
from backend.engines.incident_manager import incident_manager


class TestAiSecurityAnalyst(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        incident_manager.reset_store(seed=True)
        self.sample_incident = {
            "incident_id": "INC-2026-0001",
            "threat_type": "Phishing",
            "classification": "Brand Impersonation & Urgent Credential Lure",
            "risk_score": 92,
            "risk_level": "CRITICAL",
            "explanation": "Critical phishing lure identified imitating PayPal with credential harvesting triggers.",
            "indicators": [
                {"indicator": "High Urgency Keyword", "details": "Urgent coercive wording"},
                {"indicator": "Credential Harvesting", "details": "Requests password and OTP"}
            ],
            "recommended_actions": [
                "Do not click the provided link or input credentials.",
                "Verify sender identity via verified out-of-band channels."
            ],
            "source_data": {
                "sender": "security@paypal-notice.com",
                "url": "http://paypa1-secure-verify.net/signin"
            }
        }

    def test_01_ai_service_mocked_success(self):
        """1. AI service returns structured analysis when LLM call succeeds."""
        mock_response = (
            '{\n'
            '  "summary": "High-confidence PayPal credential harvesting campaign targeting user credentials.",\n'
            '  "why_it_matters": "Credential compromise can lead to financial loss and unauthorized account access.",\n'
            '  "key_evidence": ["High Urgency Keyword present", "Deceptive domain paypa1-secure-verify.net"],\n'
            '  "investigation_steps": ["Inspect email gateway logs", "Block destination domain"],\n'
            '  "recommended_actions": ["Notify user not to interact", "Add domain to egress blocklist"],\n'
            '  "limitations": "Advisory interpretation based solely on submitted telemetry."\n'
            '}'
        )

        with patch.dict(os.environ, {"AI_API_KEY": "test-key-12345"}):
            with patch("backend.services.ai_security_analyst.call_llm_completion", return_value=mock_response):
                result = analyze_incident(self.sample_incident)

        self.assertEqual(result["status"], "ai")
        self.assertFalse(result["is_fallback"])
        self.assertIn("PayPal", result["summary"])
        self.assertIn("why_it_matters", result)
        self.assertEqual(len(result["key_evidence"]), 2)
        self.assertEqual(len(result["investigation_steps"]), 2)
        self.assertEqual(len(result["recommended_actions"]), 2)
        self.assertIn("limitations", result)

    def test_02_missing_api_key_fallback(self):
        """2. When AI_API_KEY is missing, gracefully return deterministic fallback."""
        with patch.dict(os.environ, {"AI_API_KEY": ""}, clear=True):
            result = analyze_incident(self.sample_incident)

        self.assertEqual(result["status"], "fallback")
        self.assertTrue(result["is_fallback"])
        self.assertTrue(len(result["summary"]) > 0)
        self.assertTrue(len(result["why_it_matters"]) > 0)
        self.assertTrue(len(result["key_evidence"]) > 0)
        self.assertTrue(len(result["investigation_steps"]) > 0)
        self.assertTrue(len(result["recommended_actions"]) > 0)
        self.assertTrue("limitations" in result and len(result["limitations"]) > 0)

    def test_03_api_failure_fallback(self):
        """3. When external API fails or errors, return graceful fallback without crashing."""
        with patch.dict(os.environ, {"AI_API_KEY": "sk-invalid-key"}):
            with patch("backend.services.ai_security_analyst.call_llm_completion", return_value=None):
                result = analyze_incident(self.sample_incident)

        self.assertEqual(result["status"], "fallback")
        self.assertTrue(result["is_fallback"])
        self.assertIn("INC-2026-0001", result["summary"])
        self.assertTrue(len(result["key_evidence"]) >= 2)

    def test_04_incident_not_found(self):
        """4. Returns 404 when requested incident ID does not exist."""
        resp_analysis = self.client.post("/incidents/INC-NONEXISTENT-9999/ai-analysis")
        self.assertEqual(resp_analysis.status_code, 404)
        self.assertIn("not found", resp_analysis.json()["detail"].lower())

        resp_chat = self.client.post(
            "/incidents/INC-NONEXISTENT-9999/ai-chat",
            json={"question": "Why is this risky?"}
        )
        self.assertEqual(resp_chat.status_code, 404)

    def test_05_valid_ai_response_endpoint(self):
        """5. Valid AI response returned from POST /incidents/{id}/ai-analysis."""
        resp = self.client.post("/incidents/INC-2026-0001/ai-analysis")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        for key in ["summary", "why_it_matters", "key_evidence", "investigation_steps", "recommended_actions", "limitations", "status", "is_fallback"]:
            self.assertIn(key, data)
        self.assertIsInstance(data["key_evidence"], list)
        self.assertIsInstance(data["investigation_steps"], list)
        self.assertIsInstance(data["recommended_actions"], list)

    def test_06_malformed_ai_response(self):
        """6. Malformed AI response (invalid JSON / non-JSON) falls back gracefully."""
        malformed_raw = "I am a language model and here is my summary: not a json string {{{broken"
        with patch.dict(os.environ, {"AI_API_KEY": "valid-looking-key"}):
            with patch("backend.services.ai_security_analyst.call_llm_completion", return_value=malformed_raw):
                result = analyze_incident(self.sample_incident)

        self.assertEqual(result["status"], "fallback")
        self.assertTrue(result["is_fallback"])
        self.assertIn("summary", result)
        self.assertIn("key_evidence", result)

    def test_07_ai_chat_endpoint(self):
        """7. AI chat endpoint answers evidence-grounded questions and notes insufficient evidence."""
        # Evidence-grounded question
        resp = self.client.post(
            "/incidents/INC-2026-0001/ai-chat",
            json={"question": "Why was this incident classified as critical?"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("answer", data)
        self.assertIn("CRITICAL", data["answer"])
        self.assertTrue("92" in data["answer"] or "credential" in data["answer"].lower())

        # Unsupported question (attacker attribution)
        resp_unsupported = self.client.post(
            "/incidents/INC-2026-0001/ai-chat",
            json={"question": "Which nation state or APT actor executed this campaign?"}
        )
        self.assertEqual(resp_unsupported.status_code, 200)
        ans_text = resp_unsupported.json()["answer"]
        self.assertIn("Insufficient evidence in the available incident data", ans_text)


if __name__ == "__main__":
    unittest.main()
