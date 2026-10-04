"""
Unit Tests for SecurityDatasetProvider
Phase 2 Step 3: Validates dataset loading, chunking, and file handling using fixtures.
"""

import os
import tempfile
import unittest

from services.providers.security_dataset_provider import SecurityDatasetProvider


class TestSecurityDatasetProvider(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        # Fixture 1: Standard valid mini dataset (3 rows)
        self.valid_csv = os.path.join(self.temp_dir.name, "valid_mini.csv")
        with open(self.valid_csv, "w", encoding="utf-8") as f:
            f.write(
                "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,Label\n"
                "FLOW-01,172.16.0.1,50000,192.168.10.50,80,6,07/07/2017 01:00:00,DDoS\n"
                "FLOW-02,172.16.0.1,50001,192.168.10.50,22,6,07/07/2017 01:01:00,SSH-Patator\n"
                "FLOW-03,192.168.10.14,50002,192.168.10.3,53,17,07/07/2017 01:02:00,BENIGN\n"
            )

        # Fixture 2: Completely empty CSV file
        self.empty_csv = os.path.join(self.temp_dir.name, "empty.csv")
        with open(self.empty_csv, "w", encoding="utf-8") as f:
            pass

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dataset_loading_valid_file(self):
        """Test 1: Valid dataset loading and metadata discovery."""
        provider = SecurityDatasetProvider(dataset_path=self.valid_csv)
        self.assertTrue(provider.file_exists())
        info = provider.get_dataset_info()
        self.assertTrue(info["exists"])
        self.assertEqual(info["column_count"], 8)
        self.assertEqual(info["columns"], ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label"])
        self.assertEqual(info["dataset_source"], "CIC-IDS2017")

    def test_nonexistent_file_handling(self):
        """Test 2: Non-existent file does not crash and reports not exists."""
        nonexistent = os.path.join(self.temp_dir.name, "missing.csv")
        provider = SecurityDatasetProvider(dataset_path=nonexistent)
        self.assertFalse(provider.file_exists())
        info = provider.get_dataset_info()
        self.assertFalse(info["exists"])
        self.assertIn("error", info)

    def test_empty_file_handling(self):
        """Test 3: Empty file produces 0 columns and handles gracefully."""
        provider = SecurityDatasetProvider(dataset_path=self.empty_csv)
        info = provider.get_dataset_info()
        self.assertTrue(info["exists"])
        self.assertEqual(info["column_count"], 0)

        chunks = list(provider.stream_raw_chunks())
        self.assertEqual(len(chunks), 0)

    def test_chunked_streaming(self):
        """Test 4: Chunked generator yields configured batch sizes."""
        # Use chunk size of 1
        provider = SecurityDatasetProvider(dataset_path=self.valid_csv, chunk_size=1)
        chunks = list(provider.stream_raw_chunks())
        self.assertEqual(len(chunks), 3)
        self.assertEqual(len(chunks[0]), 1)
        self.assertEqual(chunks[0][0]["Flow ID"], "FLOW-01")
        self.assertEqual(chunks[1][0]["Flow ID"], "FLOW-02")
        self.assertEqual(chunks[2][0]["Flow ID"], "FLOW-03")

    def test_import_limit_enforcement(self):
        """Test 5: Respects limit parameter for development/testing."""
        provider = SecurityDatasetProvider(dataset_path=self.valid_csv, chunk_size=2, limit=2)
        events, stats = provider.load_normalized_events(limit=2)
        self.assertEqual(len(events), 2)
        self.assertEqual(stats["rows_imported"], 2)


if __name__ == "__main__":
    unittest.main()
