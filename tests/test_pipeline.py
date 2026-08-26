"""Unit and integration tests for APK-Static-Analyzer using standard unittest."""
import os
import unittest
import tempfile
import shutil
from tests.create_test_apk import create_synthetic_apk, create_synthetic_apks
from analyze import run_pipeline


class TestApkStaticAnalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sample_apk = os.path.join(self.temp_dir, "test_target.apk")
        self.sample_apks = os.path.join(self.temp_dir, "test_bundle.apks")
        create_synthetic_apk(self.sample_apk)
        create_synthetic_apks(self.sample_apks)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_pipeline_execution_single_apk(self):
        output_dir = os.path.join(self.temp_dir, "out_apk")
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
        self.assertIn("Google Play Billing Library", report.billing.providers_detected)

        # Verify PurchaseBooleanDetector located isPurchased in classes3.dex
        boolean_candidates = report.boolean_candidates
        self.assertGreater(len(boolean_candidates), 0)
        top_candidate = boolean_candidates[0]
        self.assertEqual(top_candidate.method_name, "isPurchased")
        self.assertEqual(top_candidate.return_type, "boolean")
        self.assertEqual(top_candidate.dex_file, "classes3.dex")
        self.assertIn("com.example.billing.PurchaseManager", top_candidate.class_name)

        # Verify Network Endpoint extraction
        endpoints = report.network_endpoints
        purchase_eps = [e for e in endpoints if e.is_purchase_related]
        self.assertGreater(len(purchase_eps), 0)
        self.assertTrue(any("subscription/verify" in e.url for e in purchase_eps))

    def test_full_pipeline_execution_apks_bundle(self):
        output_dir = os.path.join(self.temp_dir, "out_apks")
        report = run_pipeline(
            apk_path=self.sample_apks,
            output_dir=output_dir,
            enable_gemini=False
        )

        self.assertIsNotNone(report)
        self.assertEqual(report.apk_info.input_type, "APKS")
        self.assertTrue(os.path.exists(os.path.join(output_dir, "analysis.json")))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "report.html")))

        # Verify Contained APKs in APKS bundle
        self.assertGreaterEqual(len(report.apk_info.contained_apks), 2)
        base_splits = [a for a in report.apk_info.contained_apks if a.get("is_base")]
        self.assertEqual(len(base_splits), 1)

        # Verify aggregated Multi-DEX discovery across all splits
        self.assertGreaterEqual(len(report.dex_files), 4)

        # Verify Boolean Purchase Candidate attribution
        boolean_candidates = report.boolean_candidates
        self.assertGreater(len(boolean_candidates), 0)
        top_candidate = boolean_candidates[0]
        self.assertEqual(top_candidate.method_name, "isPurchased")
        self.assertTrue(top_candidate.source_apk.endswith(".apk"))

    def test_classifier_detection(self):
        output_dir = os.path.join(self.temp_dir, "out_classifier")
        report = run_pipeline(
            apk_path=self.sample_apk,
            output_dir=output_dir,
            enable_gemini=False
        )
        classification = report.classification.classification.value
        self.assertIn(classification, ["SERVER_SIDE", "MIXED", "CLIENT_SIDE", "UNKNOWN"])


if __name__ == "__main__":
    unittest.main()
