"""
Unit Tests for CRISP Controlled Security Event Simulator
Phase 2 Step 6: Tests live event simulation, SQLite insertion,
live correlation pipeline, risk engine integration, and live monitoring statistics.
"""

import os
import sqlite3
import tempfile
import time
import unittest

from services.event_simulator import (
    SIMULATION_TYPES,
    SecurityEventSimulator,
    generate_brute_force,
    generate_critical_event,
    generate_event,
    generate_malware_event,
    generate_port_scan,
    generate_web_attack,
)


class TestEventSimulator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_simulator_crisp.db")
        self.sim = SecurityEventSimulator(self.db_path)

    def tearDown(self):
        self.sim.stop_simulation()
        self.temp_dir.cleanup()

    def test_generate_brute_force_event(self):
        """Test 1: Brute force event generation, storage, and correlation."""
        res = self.sim.generate_brute_force()

        self.assertEqual(res["status"], "success")
        self.assertTrue(res["simulation_mode"])
        self.assertIn("SIMULATION MODE", res["disclaimer"])
        self.assertEqual(res["event"]["event_type"], "Brute Force")
        self.assertEqual(res["event"]["destination_port"], 22)

        # Check SQLite insertion
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE event_id = ?", (res["event"]["id"],))
            self.assertEqual(cursor.fetchone()[0], 1)

        # Check finding correlation
        self.assertIn("finding", res)
        self.assertTrue(res["finding"]["finding_id"].startswith("FND-"))
        self.assertGreater(res["risk_score"], 0.0)

    def test_generate_port_scan_event(self):
        """Test 2: Port scan reconnaissance generation."""
        res = self.sim.generate_port_scan()

        self.assertEqual(res["event"]["event_type"], "Port Scan")
        self.assertEqual(res["event"]["severity"], "LOW")
        self.assertEqual(res["event"]["destination_port"], 80)
        self.assertIn("Reconnaissance", res["event"]["attack_category"])

    def test_generate_web_attack_event(self):
        """Test 3: Web attack / SQL Injection generation."""
        res = self.sim.generate_web_attack()

        self.assertEqual(res["event"]["event_type"], "Web Attack")
        self.assertIn("SQL Injection", res["event"]["attack_category"])
        self.assertEqual(res["event"]["destination_port"], 443)

    def test_generate_malware_event(self):
        """Test 4: Malware detection anomaly generation."""
        res = self.sim.generate_malware_event()

        self.assertEqual(res["event"]["event_type"], "Malware Detection")
        self.assertIn("Botnet", res["event"]["attack_category"])

    def test_generate_critical_event_and_alert(self):
        """Test 5: Critical event generation triggers CRITICAL risk and active alert."""
        res = self.sim.generate_critical_event()

        self.assertTrue(res["is_critical"])
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertGreaterEqual(res["risk_score"], 75.0)
        self.assertIsNotNone(res["active_alert"])
        self.assertEqual(res["active_alert"]["title"], "CRITICAL SECURITY EVENT")
        self.assertEqual(res["active_alert"]["risk_level"], "CRITICAL")
        self.assertEqual(res["active_alert"]["simulation_label"], "SIMULATION MODE")

    def test_all_simulation_types_dispatch(self):
        """Test 6: All 8 simulation types can be generated via generate_event."""
        for sim_type in SIMULATION_TYPES:
            res = self.sim.generate_event(sim_type)
            self.assertEqual(res["status"], "success")
            self.assertIn("id", res["event"])
            self.assertTrue(res["event"]["id"].startswith("SIM-"))

    def test_live_monitoring_statistics(self):
        """Test 7: Live monitoring stats returns required real-time metrics."""
        # Generate a couple of events
        self.sim.generate_port_scan()
        self.sim.generate_brute_force()
        self.sim.generate_critical_event()

        stats = self.sim.get_live_monitoring_stats()

        self.assertIn("events_per_minute", stats)
        self.assertIn("events_last_5_minutes", stats)
        self.assertIn("current_risk", stats)
        self.assertIn("critical_incidents", stats)
        self.assertIn("recent_events", stats)
        self.assertIn("active_alert", stats)

        self.assertGreaterEqual(stats["events_last_5_minutes"], 3)
        self.assertGreaterEqual(stats["critical_incidents"]["count"], 1)
        self.assertGreaterEqual(len(stats["recent_events"]), 3)
        self.assertIsNotNone(stats["active_alert"])

    def test_simulation_start_stop_controls(self):
        """Test 8: Demo controls for starting and stopping background simulation."""
        start_res = self.sim.start_simulation(interval_seconds=1.0)
        self.assertEqual(start_res["status"], "running")
        self.assertEqual(start_res["interval_seconds"], 1.0)

        status_running = self.sim.get_simulation_status()
        self.assertTrue(status_running["is_running"])

        # Allow time for at least 1 background iteration
        time.sleep(1.2)

        stop_res = self.sim.stop_simulation()
        self.assertEqual(stop_res["status"], "stopped")

        status_stopped = self.sim.get_simulation_status()
        self.assertFalse(status_stopped["is_running"])
        self.assertGreater(stop_res["total_events_generated"], 0)

    def test_module_level_helpers(self):
        """Test 9: Module-level convenience functions work properly."""
        bf = generate_brute_force(self.db_path)
        scan = generate_port_scan(self.db_path)
        web = generate_web_attack(self.db_path)
        mal = generate_malware_event(self.db_path)
        crit = generate_critical_event(self.db_path)
        gen = generate_event(db_path=self.db_path)

        for res in [bf, scan, web, mal, crit, gen]:
            self.assertEqual(res["status"], "success")
            self.assertTrue(res["simulation_mode"])


if __name__ == "__main__":
    unittest.main()
