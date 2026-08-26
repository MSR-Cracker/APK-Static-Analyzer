"""Unit and integration tests for APK-Static-Analyzer using standard unittest."""
import os
import unittest
import tempfile
import shutil
from tests.create_test_apk import create_synthetic_apk
from analyze import run_pipeline


class TestApkStaticAnalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sample_apk = os.path.join(self.temp_dir, "test_target.apk")
        create_synthetic_apk(self.sample_apk)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_pipeline_execution(self):
        output_dir = os.path.join(self.temp_dir, "out")
        report = run_pipeline(
            apk_path=self.sample_apk,
            output_dir=output_dir,
            enable_gemini=False
        )

        self.assertIsNotNone(report)
        self.assertTrue(os.path.exists(os.path.join(output_dir, "analysis.json")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "report.html")))

        # Verify Multi-DEX discovery
        self.assertGreaterEqual(len(report.dex_files), 3)

        # Verify Billing Provider Detection
        self.assertIn("Google Play Billing", report.billing.get("providers_detected", []))

        # Verify PurchaseBooleanDetector located isPurchased in classes3.dex
        boolean_candidates = report.purchase_boolean_methods
        self.assertGreater(len(boolean_candidates), 0)
        top_candidate = boolean_candidates[0]
        self.assertEqual(top_candidate.get("method_name"), "isPurchased")
        self.assertEqual(top_candidate.get("return_type"), "boolean")
        self.assertEqual(top_candidate.get("dex_file"), "classes3.dex")
        self.assertIn("com.example.billing.PurchaseManager", top_candidate.get("class_name"))

        # Verify Network Endpoint extraction
        endpoints = report.network.get("endpoints", [])
        purchase_eps = [e for e in endpoints if e.get("is_purchase_related")]
        self.assertGreater(len(purchase_eps), 0)
        self.assertTrue(any("subscription/verify" in e.get("url") for e in purchase_eps))

    def test_classifier_detection(self):
        output_dir = os.path.join(self.temp_dir, "out_classifier")
        report = run_pipeline(
            apk_path=self.sample_apk,
            output_dir=output_dir,
            enable_gemini=False
        )
        classification = report.classification.get("classification")
        self.assertIn(classification, ["SERVER_SIDE", "MIXED", "CLIENT_SIDE", "UNKNOWN"])


if __name__ == "__main__":
    unittest.main()
