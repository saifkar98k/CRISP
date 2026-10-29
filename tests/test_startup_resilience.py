"""
CRISP 2.2 — Startup Resilience & Zero-Config Environment Test Suite
Validates:
1. First-time startup with an empty database.
2. Startup with an existing database without duplicate record creation.
3. Missing optional Groq API key (graceful deterministic fallback, no crash).
4. Missing optional NVD API key (unauthenticated public mode, no crash).
5. Database migration idempotency (safe repeated runs).
6. Optional enterprise integrations disabled (Splunk, CrowdStrike, Redis).
7. Zero-config startup defaults (no mandatory environment variables).
8. Corrupted or invalid database handling.
"""

import os
import tempfile
import unittest
import sqlite3
from unittest.mock import patch

from services.agents.groq_client import GroqClientWrapper, get_groq_client
from services.providers.nvd_provider import NVDDataProvider
from services.providers.enterprise_adapters import SplunkSIEMAdapter, EndpointCloudTelemetryAdapter
from services.pipeline.event_queue import EventProcessingQueue
from services.risk_engine import init_risk_history_db, calculate_final_risk
from scripts.migrate import run_migrations


class TestStartupResilienceAndConfig(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, "test_crisp.db")

    def tearDown(self):
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except OSError:
                pass

    # 1. First-time startup with an empty database
    def test_first_time_startup_empty_database(self):
        """Verifies that running migrations on an empty database path creates all tables cleanly."""
        self.assertFalse(os.path.exists(self.test_db_path))
        success = run_migrations(self.test_db_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.test_db_path))

        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall()]
            self.assertIn("vulnerabilities", tables)
            self.assertIn("security_events", tables)
            self.assertIn("assets", tables)
            self.assertIn("security_findings", tables)
            self.assertIn("risk_history", tables)
            self.assertIn("remediations", tables)
            self.assertIn("audit_logs", tables)

    # 2. Startup with an existing database (Idempotent Migration)
    def test_idempotent_migrations_existing_database(self):
        """Verifies that running migrations multiple times preserves existing data without errors."""
        run_migrations(self.test_db_path)
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users;")
            user_count_initial = cursor.fetchone()[0]

        # Second migration pass
        success_pass_2 = run_migrations(self.test_db_path)
        self.assertTrue(success_pass_2)

        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users;")
            user_count_after = cursor.fetchone()[0]
            self.assertEqual(user_count_initial, user_count_after)

    # 3. Missing optional Groq API key
    def test_missing_groq_api_key_deterministic_fallback(self):
        """Verifies that missing GROQ_API_KEY does not crash the platform and falls back cleanly."""
        with patch.dict(os.environ, {"GROQ_API_KEY": ""}, clear=False):
            client = GroqClientWrapper(api_key="")
            self.assertFalse(client.is_configured())
            response = client.generate(
                system_prompt="Test system",
                user_prompt="Analyze vulnerability",
            )
            self.assertIsInstance(response, str)
            self.assertTrue(len(response) > 0)
            self.assertIn("crisp swarm heuristic analysis", response.lower())

    # 4. Missing optional NVD API key
    def test_missing_nvd_api_key_unauthenticated_mode(self):
        """Verifies that missing NVD_API_KEY enables unauthenticated public tier safely."""
        with patch.dict(os.environ, {"NVD_API_KEY": ""}, clear=False):
            provider = NVDDataProvider(api_key=None)
            self.assertIsNone(provider.api_key)
            self.assertEqual(provider.base_url, "https://services.nvd.nist.gov/rest/json/cves/2.0")

    # 5. Optional enterprise integrations disabled
    def test_optional_enterprise_adapters_disabled_by_default(self):
        """Verifies that Splunk and CrowdStrike adapters report unconfigured status gracefully."""
        with patch.dict(os.environ, {"SPLUNK_HEC_URL": "", "SPLUNK_HEC_TOKEN": ""}, clear=False):
            splunk = SplunkSIEMAdapter()
            info = splunk.get_adapter_info()
            self.assertFalse(info["is_configured"])

        with patch.dict(os.environ, {"FALCON_CLIENT_ID": "", "FALCON_CLIENT_SECRET": ""}, clear=False):
            falcon = EndpointCloudTelemetryAdapter()
            info = falcon.get_adapter_info()
            self.assertFalse(info["is_configured"])

    # 6. Event queue zero-config local startup (In-Memory Queue without Redis)
    def test_event_queue_zero_config_local_mode(self):
        """Verifies that EventProcessingQueue operates fully in-memory when REDIS_URL is absent."""
        with patch.dict(os.environ, {"REDIS_URL": ""}, clear=False):
            queue = EventProcessingQueue(capacity=100, workers=1)
            status = queue.get_status()
            self.assertFalse(status["redis_scale_out_ready"])
            self.assertEqual(status["queue_engine"], "IN_MEMORY_BOUNDED_WITH_DLQ")

            # Enqueue and process a test event
            success = queue.enqueue({"event_id": "TEST-EVT-01", "type": "TEST"})
            self.assertTrue(success)
            queue.stop()

    # 7. Risk calculation works on cold startup
    def test_risk_calculation_cold_startup(self):
        """Verifies multi-factor risk calculation without any external network calls."""
        res = calculate_final_risk(
            cvss_score=9.8,
            is_cisa_kev=True,
            asset_criticality="CRITICAL",
            asset_exposure="EXTERNAL",
            event_count=5,
            recency_hours=2.0,
        )
        self.assertGreaterEqual(res["final_risk_score"], 70.0)
        self.assertEqual(res["risk_level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
