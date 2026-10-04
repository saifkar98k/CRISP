"""
CRISP Unit Tests - NVD Normalization Tests
Verifies normalization of NVD 2.0 CVE objects into internal CRISP Vulnerability schema.
"""

import unittest
from services.providers.nvd_provider import normalize_nvd_cve, map_cvss_severity


class TestNVDNormalization(unittest.TestCase):

    def setUp(self):
        self.sample_valid_nvd_cve = {
            "cve": {
                "id": "CVE-2024-3400",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2024-04-12T17:15:00.000",
                "lastModified": "2024-04-15T12:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A command injection vulnerability in the GlobalProtect feature of PAN-OS software.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-77"}],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:10.2:*:*:*:*:*:*:*",
                                    }
                                ],
                            }
                        ]
                    }
                ],
                "references": [
                    {"url": "https://security.paloaltonetworks.com/CVE-2024-3400", "source": "cve@mitre.org"}
                ],
            }
        }

    def test_valid_nvd_normalization(self):
        """Test normalization with a valid, fully-populated NVD 2.0 CVE."""
        result = normalize_nvd_cve(self.sample_valid_nvd_cve)

        self.assertEqual(result["cve_id"], "CVE-2024-3400")
        self.assertEqual(result["cvss_score"], 10.0)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertIn("command injection", result["description"])
        self.assertEqual(result["source"], "NVD")
        self.assertIn("CWE-77", result["cwe"])
        self.assertIn("Paloaltonetworks Pan-Os", result["affected_products"])
        self.assertEqual(result["references"], ["https://security.paloaltonetworks.com/CVE-2024-3400"])
        # Unfabricated fields
        self.assertIsNone(result["exploit_available"])
        self.assertIsNone(result["patch_available"])

    def test_missing_cvss_score(self):
        """Test that missing CVSS metrics do not cause failure or fabricated scores."""
        raw = {
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en", "value": "Vulnerability under analysis with no metrics yet."}],
                "metrics": {},
            }
        }
        result = normalize_nvd_cve(raw)

        self.assertEqual(result["cve_id"], "CVE-2024-9999")
        self.assertIsNone(result["cvss_score"])
        self.assertEqual(result["severity"], "NONE")
        self.assertEqual(result["source"], "NVD")

    def test_missing_description(self):
        """Test handling of CVE record without English or any description."""
        raw = {
            "cve": {
                "id": "CVE-2024-8888",
                "descriptions": [],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
            }
        }
        result = normalize_nvd_cve(raw)

        self.assertEqual(result["cve_id"], "CVE-2024-8888")
        self.assertIsNone(result["description"])
        self.assertEqual(result["cvss_score"], 7.5)
        self.assertEqual(result["severity"], "HIGH")

    def test_cvss_v30_fallback(self):
        """Test fallback to CVSS v3.0 when v3.1 is unavailable."""
        raw = {
            "cve": {
                "id": "CVE-2018-0001",
                "descriptions": [{"lang": "en", "value": "Legacy CVE with CVSS v3.0."}],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "cvssData": {
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ]
                },
            }
        }
        result = normalize_nvd_cve(raw)
        self.assertEqual(result["cvss_score"], 6.5)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_cvss_v2_fallback(self):
        """Test fallback to CVSS v2 when v3 is unavailable."""
        raw = {
            "cve": {
                "id": "CVE-2010-0002",
                "descriptions": [{"lang": "en", "value": "Old CVE with CVSS v2."}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {
                                "baseScore": 5.0,
                            },
                            "baseSeverity": "MEDIUM",
                        }
                    ]
                },
            }
        }
        result = normalize_nvd_cve(raw)
        self.assertEqual(result["cvss_score"], 5.0)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_invalid_input(self):
        """Test that invalid types raise ValueError."""
        with self.assertRaises(ValueError):
            normalize_nvd_cve("invalid string")


if __name__ == "__main__":
    unittest.main()
