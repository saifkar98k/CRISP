"""
CRISP Unit Tests - CISA KEV Normalization Tests
Verifies conversion of raw CISA KEV JSON records into the CRISP normalized schema.
"""

import unittest
from services.providers.cisa_kev_provider import normalize_cisa_kev


class TestCISAKEVNormalization(unittest.TestCase):

    def test_valid_cisa_kev_normalization(self):
        """Test normalization of a fully-populated CISA KEV record."""
        raw = {
            "cveID": "CVE-2023-34362",
            "vendorProject": "Progress",
            "product": "MOVEit Transfer",
            "vulnerabilityName": "Progress MOVEit Transfer SQL Injection Vulnerability",
            "dateAdded": "2023-06-02",
            "shortDescription": "Progress MOVEit Transfer contains a SQL injection flaw.",
            "requiredAction": "Apply vendor mitigation immediately.",
            "dueDate": "2023-06-23",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023",
        }

        norm = normalize_cisa_kev(raw)

        self.assertEqual(norm["cve_id"], "CVE-2023-34362")
        self.assertEqual(norm["vendor_project"], "Progress")
        self.assertEqual(norm["product"], "MOVEit Transfer")
        self.assertEqual(norm["date_added"], "2023-06-02")
        self.assertEqual(norm["due_date"], "2023-06-23")
        self.assertEqual(norm["known_ransomware_campaign_use"], "Known")
        self.assertEqual(norm["source"], "CISA_KEV")
        self.assertTrue(norm["known_exploited"])
        self.assertIn("SQL injection", norm["short_description"])

    def test_missing_optional_fields(self):
        """Test normalization when optional CISA fields are null/missing without fabricating."""
        raw = {
            "cveID": "CVE-2025-0001",
            "vendorProject": "",
            "product": "Minimal Product",
            "dateAdded": "2025-01-10",
        }

        norm = normalize_cisa_kev(raw)

        self.assertEqual(norm["cve_id"], "CVE-2025-0001")
        self.assertEqual(norm["product"], "Minimal Product")
        self.assertIsNone(norm["vendor_project"])
        self.assertIsNone(norm["required_action"])
        self.assertIsNone(norm["due_date"])
        self.assertIsNone(norm["known_ransomware_campaign_use"])
        self.assertIsNone(norm["notes"])
        self.assertTrue(norm["known_exploited"])
        self.assertEqual(norm["source"], "CISA_KEV")

    def test_invalid_input_type(self):
        """Test that passing a non-dict raises ValueError."""
        with self.assertRaises(ValueError):
            normalize_cisa_kev("not a dictionary")


if __name__ == "__main__":
    unittest.main()
