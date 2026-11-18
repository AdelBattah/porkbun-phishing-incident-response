"""
End-to-End Test Suite for SOC Phishing Forensic Parser
Validates IOC extraction, risk scoring, defanging, and MITRE ATT&CK mapping.
"""

import sys
import unittest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))
from eml_ioc_extractor import analyze_eml


class TestPhishingForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples_dir = Path(__file__).parent / "samples"
        cls.email1_path = cls.samples_dir / "incident_email1_zoho_relay_sanitized.eml"
        cls.email2_path = cls.samples_dir / "incident_email2_direct_sanitized.eml"
        cls.email3_path = cls.samples_dir / "incident_email3_birdwatching_sanitized.eml"

    def test_samples_exist(self):
        self.assertTrue(self.email1_path.exists(), "Sample email 1 must exist")
        self.assertTrue(self.email2_path.exists(), "Sample email 2 must exist")
        self.assertTrue(self.email3_path.exists(), "Sample email 3 must exist")

    def test_zoho_relay_abuse_detection(self):
        report = analyze_eml(self.email1_path, do_enrich=False, do_sanitize=True)

        assessment = report["assessment"]
        self.assertEqual(assessment["verdict"], "CRITICAL / CONFIRMED PHISHING")
        self.assertGreaterEqual(assessment["risk_score"], 100)
        self.assertIn("T1583.006 - Acquire Infrastructure: Web Services", assessment["mitre_attack"])

        # Check IOC defanging
        urls_defanged = report["iocs"]["urls_defanged"]
        self.assertTrue(any("hxxps://" in u or "[.]" in u for u in urls_defanged))

        # Check raw IOCs present for SOAR ingestion
        urls_raw = report["iocs"]["urls_raw"]
        self.assertTrue(any("https://" in u for u in urls_raw))

    def test_direct_phish_detection(self):
        report = analyze_eml(self.email2_path, do_enrich=False, do_sanitize=True)

        assessment = report["assessment"]
        self.assertEqual(assessment["verdict"], "CRITICAL / CONFIRMED PHISHING")
        self.assertGreaterEqual(assessment["risk_score"], 100)
        self.assertIn("T1036.005 - Masquerading: Match Legitimate Name or Location", assessment["mitre_attack"])

    def test_wave3_subdomain_hijack_detection(self):
        report = analyze_eml(self.email3_path, do_enrich=False, do_sanitize=True)

        assessment = report["assessment"]
        self.assertEqual(assessment["verdict"], "CRITICAL / CONFIRMED PHISHING")
        self.assertGreaterEqual(assessment["risk_score"], 100)
        self.assertIn("T1036.005 - Masquerading: Match Legitimate Name or Location", assessment["mitre_attack"])

        # Check domain and URL extraction
        urls_raw = report["iocs"]["urls_raw"]
        self.assertTrue(any("birdwatching" in u or "wwwaccountv" in u for u in urls_raw))
        emails = report["iocs"]["email_addresses"]
        self.assertTrue(any("paomusic.info" in e for e in emails))


if __name__ == "__main__":
    unittest.main()
