"""
Unit Tests for CRISP Security Data Correlation Engine
Phase 2 Step 4: Tests multi-source correlation across:
- Security Events -> Assets
- Assets -> Vulnerabilities
- Vulnerabilities -> CISA KEV
- Repeated event detection & frequency weighting
- Missing relationships ('Uncorrelated')
- Security Finding generation with auditable evidence
"""

import json
import os
import sqlite3
import tempfile
import unittest

from services.correlation_engine import (
    SecurityCorrelationEngine,
    init_correlation_db,
)


class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_crisp.db")
        init_correlation_db(self.db_path)

        # Seed test vulnerability into SQLite
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    cwe TEXT,
                    affected_products TEXT,
                    references_json TEXT,
                    source TEXT,
                    known_exploited INTEGER DEFAULT 0,
                    kev_due_date TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            # Insert CVE-2021-44228 (Log4Shell) as CISA KEV active
            cursor.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id, description, cvss_score, severity, published_date,
                    modified_date, cwe, affected_products, references_json,
                    source, known_exploited, kev_due_date, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    "CVE-2021-44228",
                    "Apache Log4j2 JNDI Remote Code Execution vulnerability",
                    10.0,
                    "CRITICAL",
                    "2021-12-10T10:00:00Z",
                    "2021-12-14T10:00:00Z",
                    "CWE-502",
                    "Apache Log4j",
                    "[]",
                    "NVD",
                    1,  # In CISA KEV
                    "2021-12-24",
                    "2021-12-10T10:00:00Z",
                    "2021-12-10T10:00:00Z",
                ),
            )
            # Insert standard CVE without KEV
            cursor.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id, description, cvss_score, severity, published_date,
                    modified_date, cwe, affected_products, references_json,
                    source, known_exploited, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    "CVE-2023-9999",
                    "Generic internal library flaw",
                    5.5,
                    "MEDIUM",
                    "2023-05-01T10:00:00Z",
                    "2023-05-01T10:00:00Z",
                    "CWE-200",
                    "LibFoo",
                    "[]",
                    "NVD",
                    0,  # Not in KEV
                    "2023-05-01T10:00:00Z",
                    "2023-05-01T10:00:00Z",
                ),
            )
            conn.commit()

        self.engine = SecurityCorrelationEngine(self.db_path)
        self.asset_maps = self.engine._load_assets()
        self.vuln_map = self.engine._load_vulnerabilities()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_event_to_asset_correlation(self):
        """Test 1: Correlating event to an asset via destination IP address."""
        event = {
            "event_id": "EVT-TEST-01",
            "destination_ip": "10.0.4.15",
            "attack_category": "Exploit Public-Facing App",
            "severity": "CRITICAL",
        }
        finding = self.engine.correlate_event(event, self.asset_maps, self.vuln_map)

        self.assertEqual(finding["asset_id"], "AST-PROD-WEB-01")
        self.assertEqual(finding["asset_name"], "prod-edge-web01.internal")
        self.assertEqual(finding["asset_criticality"], "CRITICAL")
        # Evidence includes asset match
        self.assertTrue(any("prod-edge-web01.internal" in ev for ev in finding["evidence"]))

    def test_asset_to_vulnerability_correlation(self):
        """Test 2: Correlating event and asset to known CVE."""
        event = {
            "event_id": "EVT-TEST-02",
            "destination_ip": "10.0.4.15",
            "cve_id": "CVE-2021-44228",
            "attack_category": "Exploit Public-Facing App",
            "severity": "CRITICAL",
        }
        finding = self.engine.correlate_event(event, self.asset_maps, self.vuln_map)

        self.assertEqual(finding["cve_id"], "CVE-2021-44228")
        self.assertEqual(finding["cvss_score"], 10.0)
        self.assertTrue(any("CVE-2021-44228" in ev for ev in finding["evidence"]))

    def test_vulnerability_to_cisa_kev_correlation(self):
        """Test 3: Correlating CVE to CISA KEV catalog triggers known_exploited and score bonus."""
        event_kev = {
            "event_id": "EVT-TEST-KEV",
            "destination_ip": "10.0.4.15",
            "cve_id": "CVE-2021-44228",
            "attack_category": "Exploit Public-Facing App",
            "severity": "CRITICAL",
        }
        finding = self.engine.correlate_event(event_kev, self.asset_maps, self.vuln_map)

        self.assertTrue(finding["known_exploited"])
        # High composite score due to CVSS 10.0 + KEV + Critical asset tier
        self.assertGreaterEqual(finding["risk_score"], 80.0)
        self.assertEqual(finding["risk_level"], "CRITICAL")
        self.assertTrue(any("CISA KEV Catalog" in ev for ev in finding["evidence"]))

    def test_repeated_event_frequency_detection(self):
        """Test 4: Repeated events targeting the same asset increase frequency and score."""
        event = {
            "event_id": "EVT-TEST-FREQ",
            "destination_ip": "10.0.4.15",
            "attack_category": "Denial of Service (DDoS)",
            "severity": "CRITICAL",
        }
        finding_single = self.engine.correlate_event(event, self.asset_maps, self.vuln_map, event_frequency=1)
        finding_repeated = self.engine.correlate_event(event, self.asset_maps, self.vuln_map, event_frequency=5)

        self.assertGreater(finding_repeated["risk_score"], finding_single["risk_score"])
        self.assertTrue(any("5 correlated events" in ev for ev in finding_repeated["evidence"]))

    def test_missing_relationships_uncorrelated(self):
        """Test 5: Unmatched hosts or CVEs are marked Uncorrelated without fabricating data."""
        event = {
            "event_id": "EVT-TEST-UNKNOWN",
            "destination_ip": "203.0.113.99",  # Not in asset catalog
            "cve_id": None,
            "attack_category": "PortScan",
            "severity": "LOW",
        }
        finding = self.engine.correlate_event(event, self.asset_maps, self.vuln_map)

        self.assertIsNone(finding["asset_id"])
        self.assertEqual(finding["asset_name"], "Uncorrelated Asset")
        self.assertIsNone(finding["cve_id"])
        self.assertFalse(finding["known_exploited"])
        self.assertTrue(any("Asset relationship: Uncorrelated" in ev for ev in finding["evidence"]))
        self.assertTrue(any("Vulnerability relationship: Uncorrelated" in ev for ev in finding["evidence"]))

    def test_finding_generation_and_nist_mapping(self):
        """Test 6: Valid finding fields and NIST CSF 2.0 function assignment."""
        event = {
            "event_id": "EVT-TEST-NIST",
            "destination_ip": "10.0.4.18",
            "attack_category": "Brute Force (SSH)",
            "severity": "HIGH",
        }
        finding = self.engine.correlate_event(event, self.asset_maps, self.vuln_map)

        self.assertTrue(finding["finding_id"].startswith("FND-"))
        self.assertEqual(finding["nist_function"], "PROTECT")
        self.assertIn(finding["risk_level"], ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.assertIsInstance(finding["evidence"], list)
        self.assertGreater(len(finding["evidence"]), 2)

    def test_sqlite_persistence_and_queries(self):
        """Test 7: Saving and retrieving findings from SQLite."""
        event = {
            "event_id": "EVT-TEST-PERSIST",
            "destination_ip": "10.0.4.15",
            "cve_id": "CVE-2021-44228",
            "attack_category": "Exploit Public-Facing App",
            "severity": "CRITICAL",
        }
        finding = self.engine.correlate_event(event, self.asset_maps, self.vuln_map)
        self.engine.save_findings([finding])

        # Retrieve
        stored = self.engine.get_findings(limit=10)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["finding_id"], finding["finding_id"])
        self.assertEqual(stored[0]["asset_id"], "AST-PROD-WEB-01")
        self.assertEqual(stored[0]["cve_id"], "CVE-2021-44228")
        self.assertTrue(stored[0]["known_exploited"])
        self.assertIsInstance(stored[0]["evidence"], list)


if __name__ == "__main__":
    unittest.main()
