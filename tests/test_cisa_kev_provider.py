"""
CRISP Unit Tests - CISA KEV Provider Tests
Mocks network requests to verify CISA KEV catalog retrieval, timeout handling, and network failure resilience.
"""

import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from services.providers.cisa_kev_provider import CISAKEVProvider


class TestCISAKEVProvider(unittest.TestCase):

    def setUp(self):
        self.provider = CISAKEVProvider(catalog_url="https://mock-cisa.gov/kev.json", timeout=5)
        self.mock_catalog_payload = {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2026.10.02",
            "dateReleased": "2026-10-02T15:19:38.2945Z",
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Apache Log4j2 Deserialization Vulnerability",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Apache Log4j2 contains an untrusted deserialization flaw allowing remote code execution.",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "https://logging.apache.org/log4j/2.x/security.html",
                },
                {
                    "cveID": "CVE-2024-3400",
                    "vendorProject": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection",
                    "dateAdded": "2024-04-12",
                    "shortDescription": "Command injection vulnerability in GlobalProtect feature.",
                    "requiredAction": "Apply vendor remediation patches.",
                    "dueDate": "2024-04-19",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "https://security.paloaltonetworks.com/CVE-2024-3400",
                },
            ],
        }

    @patch("urllib.request.urlopen")
    def test_valid_kev_response(self, mock_urlopen):
        """Test 1: Valid KEV response parsing."""
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = str(self.mock_catalog_payload).replace("'", '"').encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        catalog = self.provider.get_catalog(force_refresh=True)

        self.assertIn("vulnerabilities", catalog)
        self.assertEqual(len(catalog["vulnerabilities"]), 2)
        self.assertEqual(catalog["vulnerabilities"][0]["cveID"], "CVE-2021-44228")

    @patch("urllib.request.urlopen")
    def test_empty_response(self, mock_urlopen):
        """Test 2: Empty KEV catalog response."""
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'{"title": "Empty KEV", "count": 0, "vulnerabilities": []}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        catalog = self.provider.get_catalog(force_refresh=True)

        self.assertEqual(catalog.get("vulnerabilities"), [])

    @patch("urllib.request.urlopen")
    def test_invalid_response(self, mock_urlopen):
        """Test 3: Invalid JSON or malformed response."""
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b"<html>502 Bad Gateway</html>"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        catalog = self.provider.get_catalog(force_refresh=True)

        self.assertIn("error", catalog)
        self.assertEqual(catalog.get("vulnerabilities"), [])

    @patch("urllib.request.urlopen")
    def test_network_failure(self, mock_urlopen):
        """Test 4: Network timeout or connection failure."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        catalog = self.provider.get_catalog(force_refresh=True)

        self.assertIn("error", catalog)
        self.assertIn("Connection refused", catalog["error"])


if __name__ == "__main__":
    unittest.main()
