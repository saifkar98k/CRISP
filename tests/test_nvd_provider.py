"""
CRISP Unit Tests - NVD Provider & Sync Service Tests
Mocks external API calls to verify pagination, error handling, SQLite persistence, and duplicate handling.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from services.nvd_sync_service import get_nvd_sync_status, get_vulnerabilities, init_db, sync_nvd
from services.providers.nvd_provider import NVDDataProvider


class TestNVDProviderAndSync(unittest.TestCase):

    def setUp(self):
        # Create a fresh temporary SQLite database for test isolation
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        init_db(self.temp_db_path)

        self.mock_cve_item_1 = {
            "cve": {
                "id": "CVE-2024-1111",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Initial description of CVE 1"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-78"}]}],
                "configurations": [],
                "references": [{"url": "https://example.com/cve1"}],
            }
        }

        self.mock_cve_item_2 = {
            "cve": {
                "id": "CVE-2024-2222",
                "published": "2024-01-03T00:00:00.000",
                "lastModified": "2024-01-04T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Description of CVE 2"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 5.3,
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "configurations": [],
                "references": [],
            }
        }

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_sync_valid_nvd_response(self):
        """Test syncing valid NVD response: 2 fetched, 2 inserted."""
        mock_provider = MagicMock(spec=NVDDataProvider)
        mock_provider.get_cves.return_value = {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": [self.mock_cve_item_1, self.mock_cve_item_2],
        }

        stats = sync_nvd(provider=mock_provider, db_path=self.temp_db_path)

        self.assertEqual(stats["fetched"], 2)
        self.assertEqual(stats["inserted"], 2)
        self.assertEqual(stats["updated"], 0)
        self.assertEqual(stats["failed"], 0)
        self.assertEqual(stats["status"], "Connected")

        # Verify records in database
        vulns = get_vulnerabilities(db_path=self.temp_db_path)
        self.assertEqual(len(vulns), 2)
        cve_ids = {v["cve_id"] for v in vulns}
        self.assertIn("CVE-2024-1111", cve_ids)
        self.assertIn("CVE-2024-2222", cve_ids)

    def test_duplicate_cve_handling(self):
        """Test that re-syncing an existing CVE updates it rather than duplicating."""
        mock_provider = MagicMock(spec=NVDDataProvider)
        # First sync
        mock_provider.get_cves.return_value = {
            "vulnerabilities": [self.mock_cve_item_1],
        }
        stats1 = sync_nvd(provider=mock_provider, db_path=self.temp_db_path)
        self.assertEqual(stats1["inserted"], 1)
        self.assertEqual(stats1["updated"], 0)

        # Updated payload for the same CVE
        updated_item_1 = {
            "cve": {
                "id": "CVE-2024-1111",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-02-10T00:00:00.000",
                "vulnStatus": "Modified",
                "descriptions": [{"lang": "en", "value": "UPDATED description of CVE 1"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-78"}]}],
                "configurations": [],
                "references": [{"url": "https://example.com/cve1"}],
            }
        }

        # Second sync with updated CVE and a new CVE
        mock_provider.get_cves.return_value = {
            "vulnerabilities": [updated_item_1, self.mock_cve_item_2],
        }
        stats2 = sync_nvd(provider=mock_provider, db_path=self.temp_db_path)

        self.assertEqual(stats2["fetched"], 2)
        self.assertEqual(stats2["inserted"], 1)  # Only CVE-2024-2222 is new
        self.assertEqual(stats2["updated"], 1)   # CVE-2024-1111 is updated
        self.assertEqual(stats2["failed"], 0)

        # Verify database still has exactly 2 records, not 3
        vulns = get_vulnerabilities(db_path=self.temp_db_path)
        self.assertEqual(len(vulns), 2)

        # Check updated description
        cve1 = next(v for v in vulns if v["cve_id"] == "CVE-2024-1111")
        self.assertEqual(cve1["description"], "UPDATED description of CVE 1")
        self.assertEqual(cve1["cvss_score"], 10.0)

    def test_api_failure_handling(self):
        """Test graceful handling when NVD provider reports an error (HTTP 503/429/timeout)."""
        mock_provider = MagicMock(spec=NVDDataProvider)
        mock_provider.get_cves.return_value = {
            "error": "NVD API service temporarily unavailable (HTTP 503).",
            "vulnerabilities": [],
        }

        stats = sync_nvd(provider=mock_provider, db_path=self.temp_db_path)

        self.assertEqual(stats["fetched"], 0)
        self.assertEqual(stats["inserted"], 0)
        self.assertEqual(stats["updated"], 0)
        self.assertEqual(stats["failed"], 0)
        self.assertIn("error", stats)

        # Check status reported in database
        status_info = get_nvd_sync_status(db_path=self.temp_db_path)
        self.assertEqual(status_info["connection"], "Error")

    def test_empty_results_handling(self):
        """Test when NVD returns empty results list."""
        mock_provider = MagicMock(spec=NVDDataProvider)
        mock_provider.get_cves.return_value = {
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
            "vulnerabilities": [],
        }

        stats = sync_nvd(provider=mock_provider, db_path=self.temp_db_path)
        self.assertEqual(stats["fetched"], 0)
        self.assertEqual(stats["inserted"], 0)
        self.assertEqual(stats["updated"], 0)
        self.assertEqual(stats["failed"], 0)

    def test_metadata_status_tracking(self):
        """Test that sync metadata accurately stores last sync timestamp and counts."""
        mock_provider = MagicMock(spec=NVDDataProvider)
        mock_provider.get_cves.return_value = {
            "vulnerabilities": [self.mock_cve_item_1],
        }
        sync_nvd(provider=mock_provider, db_path=self.temp_db_path)

        meta = get_nvd_sync_status(db_path=self.temp_db_path)
        self.assertEqual(meta["connection"], "Connected")
        self.assertIsNotNone(meta["last_synchronization"])
        self.assertEqual(meta["total_nvd_vulnerabilities"], 1)


if __name__ == "__main__":
    unittest.main()
