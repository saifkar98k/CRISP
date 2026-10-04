"""
Unit Tests for Security Dataset Import & SQLite Persistence
Phase 2 Step 3: Tests SQLite storage, chunking, deduplication, indexing, and risk scoring.
"""

import os
import sqlite3
import tempfile
import unittest

from services.security_event_service import (
    get_attacks_by_category,
    get_attacks_by_severity,
    get_top_source_ips,
    import_dataset_into_db,
    init_security_events_db,
)


class TestDatasetImport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_crisp.db")

        # Fixture CSV with 4 rows: 2 valid, 1 duplicate, 1 empty/invalid
        self.fixture_csv = os.path.join(self.temp_dir.name, "fixture_events.csv")
        with open(self.fixture_csv, "w", encoding="utf-8") as f:
            f.write(
                "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Label\n"
                "F-001,172.16.0.1,50000,192.168.10.50,80,6,07/07/2017 01:00:00,DDoS\n"
                "F-002,172.16.0.1,50001,192.168.10.50,22,6,07/07/2017 01:01:00,SSH-Patator\n"
                "F-001,172.16.0.1,50000,192.168.10.50,80,6,07/07/2017 01:00:00,DDoS\n"  # Duplicate
                ",,,,,,, \n"  # Invalid empty row
            )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_database_initialization_and_indexes(self):
        """Test 1: Schema initialization creates security_events table and required indexes."""
        init_security_events_db(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
            self.assertIsNotNone(cursor.fetchone())

            # Check indexes
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
            indexes = {row[0] for row in cursor.fetchall()}
            self.assertIn("idx_sec_events_timestamp", indexes)
            self.assertIn("idx_sec_events_severity", indexes)
            self.assertIn("idx_sec_events_dataset_source", indexes)

    def test_chunked_import_and_deduplication(self):
        """Test 2: Chunked import correctly filters duplicates and invalid rows."""
        stats = import_dataset_into_db(
            dataset_path=self.fixture_csv,
            chunk_size=2,
            db_path=self.db_path,
            dataset_source="CIC-IDS2017",
        )

        self.assertEqual(stats["rows_read"], 4)
        self.assertEqual(stats["rows_imported"], 2)
        self.assertEqual(stats["duplicates"], 1)
        self.assertEqual(stats["invalid_rows"], 1)
        self.assertEqual(stats["total_stored"], 2)

        # Verify stored rows in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_id, dataset_source, severity, crisp_risk_score FROM security_events ORDER BY event_id")
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 2)
            # Row 1: DDoS
            self.assertEqual(rows[0][0], "F-001")
            self.assertEqual(rows[0][1], "CIC-IDS2017")
            self.assertEqual(rows[0][2], "CRITICAL")
            self.assertGreater(rows[0][3], 50.0)  # Risk score calculated

            # Row 2: SSH-Patator
            self.assertEqual(rows[1][0], "F-002")
            self.assertEqual(rows[1][1], "CIC-IDS2017")
            self.assertEqual(rows[1][2], "HIGH")

    def test_reimport_duplicate_detection(self):
        """Test 3: Re-importing the same dataset file treats previously-saved rows as duplicates."""
        stats1 = import_dataset_into_db(
            dataset_path=self.fixture_csv,
            db_path=self.db_path,
        )
        self.assertEqual(stats1["rows_imported"], 2)

        # Run re-import
        stats2 = import_dataset_into_db(
            dataset_path=self.fixture_csv,
            db_path=self.db_path,
        )
        # All valid rows now seen in existing DB
        self.assertEqual(stats2["rows_imported"], 0)
        self.assertEqual(stats2["duplicates"], 3)  # 2 existing + 1 internal duplicate
        self.assertEqual(stats2["invalid_rows"], 1)

    def test_aggregation_queries(self):
        """Test 4: Aggregation query methods return accurate counts."""
        import_dataset_into_db(dataset_path=self.fixture_csv, db_path=self.db_path)

        by_cat = get_attacks_by_category(self.db_path)
        self.assertIn("Denial of Service (DDoS)", by_cat)
        self.assertEqual(by_cat["Denial of Service (DDoS)"], 1)
        self.assertIn("Brute Force (SSH)", by_cat)

        by_sev = get_attacks_by_severity(self.db_path)
        self.assertEqual(by_sev.get("CRITICAL"), 1)
        self.assertEqual(by_sev.get("HIGH"), 1)

        top_ips = get_top_source_ips(self.db_path)
        self.assertEqual(len(top_ips), 1)
        self.assertEqual(top_ips[0]["source_ip"], "172.16.0.1")
        self.assertEqual(top_ips[0]["count"], 2)


if __name__ == "__main__":
    unittest.main()
