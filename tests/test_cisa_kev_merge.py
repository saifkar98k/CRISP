"""
CRISP Unit Tests - CISA KEV Merging & Risk Engine Integration Tests
Verifies merging NVD and CISA records into SQLite, duplicate prevention, and risk engine weighting.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock

from services.cisa_kev_sync_service import (
    get_cisa_kev_sync_status,
    get_known_exploited_vulnerabilities,
    migrate_db_for_kev,
    sync_cisa_kev,
)
from services.nvd_sync_service import init_db
from services.providers.cisa_kev_provider import CISAKEVProvider
from services.risk_engine import KEV_RISK_WEIGHT, calculate_crisp_vulnerability_risk


class TestCISAKEVMergeAndRisk(unittest.TestCase):

    def setUp(self):
        # Fresh isolated SQLite DB for each test
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        init_db(self.temp_db_path)
        migrate_db_for_kev(self.temp_db_path)

        # Pre-seed an NVD record into SQLite (CVE-2021-44228)
        with sqlite3.connect(self.temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO vulnerabilities (
                    cve_id, description, cvss_score, severity, published_date,
                    modified_date, cwe, affected_products, references_json,
                    source, known_exploited, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "CVE-2021-44228",
                    "Apache Log4j2 JNDI RCE vulnerability.",
                    10.0,
                    "CRITICAL",
                    "2021-12-10T10:00:00Z",
                    "2021-12-15T12:00:00Z",
                    json.dumps(["CWE-502"]),
                    json.dumps(["Apache Log4j"]),
                    json.dumps(["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]),
                    "NVD",
                    0,  # Initially not marked as exploited in local DB
                    "2026-10-01 10:00:00",
                    "2026-10-01 10:00:00",
                ),
            )
            conn.commit()

        # Mock CISA KEV catalog with 2 CVEs:
        # 1. Matches existing NVD record (CVE-2021-44228)
        # 2. New CVE not in NVD database (CVE-2024-99999)
        self.mock_cisa_payload = {
            "title": "CISA KEV Catalog Mock",
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Apache Log4j2 Deserialization",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Active weaponization of Log4Shell observed.",
                    "requiredAction": "Upgrade to Log4j 2.17.1 immediately.",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "https://nvd.nist.gov",
                },
                {
                    "cveID": "CVE-2024-99999",
                    "vendorProject": "VendorX",
                    "product": "AppY",
                    "vulnerabilityName": "Zero-Day Exploit in AppY",
                    "dateAdded": "2024-05-01",
                    "shortDescription": "Active in-the-wild zero-day.",
                    "requiredAction": "Apply vendor hotfix.",
                    "dueDate": "2024-05-15",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": None,
                },
            ],
        }

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_cve_matching_and_merge(self):
        """Test 5 & 6: Matching existing NVD record + creating new CISA record."""
        mock_provider = MagicMock(spec=CISAKEVProvider)
        mock_provider.get_catalog.return_value = self.mock_cisa_payload

        stats = sync_cisa_kev(provider=mock_provider, db_path=self.temp_db_path)

        self.assertEqual(stats["fetched"], 2)
        self.assertEqual(stats["matched_nvd"], 1)
        self.assertEqual(stats["new_records"], 1)
        self.assertEqual(stats["updated_records"], 1)
        self.assertEqual(stats["failed"], 0)

        # Verify merged record (CVE-2021-44228) has both NVD and CISA data
        with sqlite3.connect(self.temp_db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM vulnerabilities WHERE cve_id = 'CVE-2021-44228'")
            merged = c.fetchone()

            # Preserved NVD CVSS & severity
            self.assertEqual(merged["cvss_score"], 10.0)
            self.assertEqual(merged["severity"], "CRITICAL")
            # Enriched CISA KEV fields
            self.assertEqual(merged["known_exploited"], 1)
            self.assertEqual(merged["kev_vendor_project"], "Apache")
            self.assertEqual(merged["kev_product"], "Log4j")
            self.assertEqual(merged["kev_due_date"], "2021-12-24")
            self.assertEqual(merged["source"], "NVD + CISA_KEV")

            # Verify brand new CISA record (CVE-2024-99999)
            c.execute("SELECT * FROM vulnerabilities WHERE cve_id = 'CVE-2024-99999'")
            new_rec = c.fetchone()
            self.assertIsNotNone(new_rec)
            self.assertIsNone(new_rec["cvss_score"])  # CVSS not invented
            self.assertEqual(new_rec["known_exploited"], 1)
            self.assertEqual(new_rec["source"], "CISA_KEV")
            self.assertEqual(new_rec["kev_vendor_project"], "VendorX")

    def test_duplicate_prevention_on_resync(self):
        """Test 7 & 8: Duplicate prevention upon re-synchronizing."""
        mock_provider = MagicMock(spec=CISAKEVProvider)
        mock_provider.get_catalog.return_value = self.mock_cisa_payload

        # First sync
        sync_cisa_kev(provider=mock_provider, db_path=self.temp_db_path)
        # Second sync
        stats2 = sync_cisa_kev(provider=mock_provider, db_path=self.temp_db_path)

        # Second sync should update 2 existing records, inserting 0 new
        self.assertEqual(stats2["new_records"], 0)
        self.assertEqual(stats2["updated_records"], 2)

        # Total count in database should remain 2 records
        with sqlite3.connect(self.temp_db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM vulnerabilities")
            total = c.fetchone()[0]
            self.assertEqual(total, 2)

    def test_known_exploited_query_filter(self):
        """Test 9: Querying only known_exploited vulnerabilities."""
        mock_provider = MagicMock(spec=CISAKEVProvider)
        mock_provider.get_catalog.return_value = self.mock_cisa_payload
        sync_cisa_kev(provider=mock_provider, db_path=self.temp_db_path)

        kevs = get_known_exploited_vulnerabilities(db_path=self.temp_db_path)
        self.assertEqual(len(kevs), 2)
        for k in kevs:
            self.assertTrue(k["known_exploited"])

    def test_risk_engine_cisa_kev_weighting(self):
        """Test 10: Risk engine integration with known_exploited factor."""
        # 1. Calculate risk WITHOUT KEV
        risk_without_kev = calculate_crisp_vulnerability_risk(
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            known_exploited=False,
            asset_criticality="HIGH",
            internet_exposed=True,
        )

        # 2. Calculate risk WITH KEV
        risk_with_kev = calculate_crisp_vulnerability_risk(
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            known_exploited=True,
            asset_criticality="HIGH",
            internet_exposed=True,
        )

        # Score with KEV should be strictly higher by KEV_RISK_WEIGHT (or hit ceiling 100)
        expected_diff = KEV_RISK_WEIGHT
        self.assertGreater(risk_with_kev["risk_score"], risk_without_kev["risk_score"])
        self.assertEqual(risk_with_kev["risk_score"] - risk_without_kev["risk_score"], expected_diff)

        # Check factors list
        kev_factor = next(
            f for f in risk_with_kev["contributing_factors"] if f["factor"] == "Known Exploited Vulnerability"
        )
        self.assertEqual(kev_factor["value"], "YES")
        self.assertEqual(kev_factor["score_contribution"], KEV_RISK_WEIGHT)

        # Check explanation mentions KEV
        self.assertIn("CISA Known Exploited Vulnerabilities catalog", risk_with_kev["explanation"])


if __name__ == "__main__":
    unittest.main()
