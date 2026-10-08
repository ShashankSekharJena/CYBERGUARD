"""
Unit and Integration Tests for Multimodal Impersonation Analyzer
Tests file validation, EXIF/PNG parsing, AI software tags, risk calculation, and explanation generation.
"""

import struct
import unittest
from backend.detectors.multimodal_detector import (
    validate_file,
    detect_multimodal_threats
)
from backend.engines.multimodal_risk_engine import calculate_multimodal_risk
from backend.engines.multimodal_explanation_engine import generate_multimodal_explanation
from backend.engines.multimodal_response_engine import generate_multimodal_recommendations


class TestMultimodalDetector(unittest.TestCase):

    def _create_minimal_png(self, width: int = 512, height: int = 512, text_chunk: str = "") -> bytes:
        # PNG signature
        png_bytes = bytearray(b"\x89PNG\r\n\x1a\n")
        # IHDR chunk
        ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        ihdr_crc = 0  # simplified for test parser
        png_bytes.extend(struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc))
        if text_chunk:
            t_data = text_chunk.encode("utf-8")
            png_bytes.extend(struct.pack(">I", len(t_data)) + b"tEXt" + t_data + struct.pack(">I", 0))
        # IEND chunk
        png_bytes.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0))
        return bytes(png_bytes)

    def test_file_validation_valid_png(self):
        png_data = self._create_minimal_png(100, 100)
        is_valid, fmt, mime = validate_file("sample.png", png_data)
        self.assertTrue(is_valid)
        self.assertEqual(fmt, "PNG")
        self.assertEqual(mime, "image/png")

    def test_file_validation_invalid_file(self):
        bad_data = b"This is just random plain text"
        is_valid, fmt, mime = validate_file("corrupt.png", bad_data)
        self.assertFalse(is_valid)

    def test_detection_of_ai_software_tag(self):
        png_with_ai = self._create_minimal_png(512, 512, "Software: Midjourney v6.0 prompt: photo of CEO")
        metadata, indicators = detect_multimodal_threats("test.png", png_with_ai)
        self.assertEqual(metadata["file_format"], "PNG")
        self.assertEqual(metadata["software_tool"], "MIDJOURNEY")
        # Ensure indicator was triggered
        has_ai_indicator = any("Midjourney" in ind["indicator"] for ind in indicators)
        self.assertTrue(has_ai_indicator)

    def test_risk_and_explanation(self):
        png_with_ai = self._create_minimal_png(1024, 1024, "Software: Stable Diffusion")
        metadata, indicators = detect_multimodal_threats("synthetic.png", png_with_ai)
        risk_score, severity = calculate_multimodal_risk(indicators)
        self.assertGreater(risk_score, 0)
        explanation = generate_multimodal_explanation(indicators, metadata, risk_score, severity)
        self.assertIn("synthetic.png", explanation)
        self.assertIn("assistive", explanation.lower())

        recommendations = generate_multimodal_recommendations(indicators, metadata, severity)
        self.assertGreater(len(recommendations), 2)


if __name__ == "__main__":
    unittest.main()
