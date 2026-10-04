"""
Unit Tests for CRISP Multi-Factor Cyber Risk Engine
Phase 2 Step 5: Validates explainable multi-factor scoring model.

Tests:
1. Low-risk case (0–24, LOW)
2. Medium-risk case (25–49, MEDIUM)
3. High-risk case (50–74, HIGH)
4. Critical-risk case (75–100, CRITICAL)
5. CISA KEV impact (active exploitation increases risk priority)
6. Asset criticality impact (critical asset tier significantly elevates risk)
7. Repeated attack impact (high attack frequency elevates incident score)
8. Missing data handling (zero-fabrication: None inputs yield 0 points, never crash)
9. Individual risk component functions
10. Configurable risk level thresholds
11. Risk history persistence and retrieval
"""

import json
import os
import sqlite3
import tempfile
import unittest

from services.risk_engine import (
    DEFAULT_RISK_THRESHOLDS,
    calculate_asset_risk,
    calculate_exposure_risk,
    calculate_final_risk,
    calculate_frequency_risk,
    calculate_recency_risk,
    calculate_threat_risk,
    calculate_vulnerability_risk,
    get_risk_history,
    get_risk_level,
    get_risk_over_time_trend,
    init_risk_history_db,
    record_risk_history,
)


class TestCrispMultiFactorRiskEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_crisp_risk.db")
        init_risk_history_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_low_risk_case(self):
        """Test 1: Low-risk scenario correctly maps to score 0–24 and LOW level."""
        res = calculate_final_risk(
            cvss_score=2.0,
            cisa_kev_status=False,
            asset_criticality="LOW",
            asset_exposure="INTERNAL",
            event_severity="LOW",
            attack_frequency=1,
            recency_hours_ago=500.0,  # > 30 days ago
        )

        self.assertGreaterEqual(res["score"], 0.0)
        self.assertLessEqual(res["score"], 24.9)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertIn("factors", res)
        self.assertIn("factor_scores", res)
        self.assertIn("explanation", res)
        self.assertIn("CVSS", res["factor_scores"])
        self.assertIn("Asset Criticality", res["factor_scores"])
        self.assertIn("Exposure", res["factor_scores"])

    def test_medium_risk_case(self):
        """Test 2: Medium-risk scenario maps to score 25–49 and MEDIUM level."""
        res = calculate_final_risk(
            cvss_score=5.5,
            cisa_kev_status=False,
            asset_criticality="MEDIUM",
            asset_exposure="DMZ",
            event_severity="MEDIUM",
            attack_frequency=2,
            recency_hours_ago=48.0,  # 2 days ago
        )

        self.assertGreaterEqual(res["score"], 25.0)
        self.assertLessEqual(res["score"], 49.9)
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertIn("factors", res)
        self.assertIn("factor_scores", res)

    def test_high_risk_case(self):
        """Test 3: High-risk scenario maps to score 50–74 and HIGH level."""
        res = calculate_final_risk(
            cvss_score=7.8,
            cisa_kev_status=False,
            asset_criticality="HIGH",
            asset_exposure="EXTERNAL",
            event_severity="HIGH",
            attack_frequency=4,
            recency_hours_ago=12.0,  # 12 hours ago
        )

        self.assertGreaterEqual(res["score"], 50.0)
        self.assertLessEqual(res["score"], 74.9)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertIn("has high vulnerability severity", res["explanation"])

    def test_critical_risk_case(self):
        """Test 4: Critical-risk scenario maps to score 75–100 and CRITICAL level."""
        res = calculate_final_risk(
            cvss_score=9.8,
            cisa_kev_status=True,
            asset_criticality="CRITICAL",
            asset_exposure="EXTERNAL",
            event_severity="CRITICAL",
            attack_frequency=6,
            recency_hours_ago=0.5,  # 30 mins ago
        )

        self.assertGreaterEqual(res["score"], 75.0)
        self.assertLessEqual(res["score"], 100.0)
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertIn("is present in the CISA KEV catalog", res["explanation"])
        self.assertIn("affects a highly critical exposed asset", res["explanation"])
        self.assertIn("has repeated recent security events", res["explanation"])

    def test_cisa_kev_impact(self):
        """Test 5: Presence in CISA KEV catalog significantly increases risk score."""
        baseline = calculate_final_risk(
            cvss_score=7.5,
            cisa_kev_status=False,
            asset_criticality="HIGH",
            asset_exposure="DMZ",
            event_severity="HIGH",
            attack_frequency=1,
            recency_hours_ago=10.0,
        )

        with_kev = calculate_final_risk(
            cvss_score=7.5,
            cisa_kev_status=True,
            asset_criticality="HIGH",
            asset_exposure="DMZ",
            event_severity="HIGH",
            attack_frequency=1,
            recency_hours_ago=10.0,
        )

        self.assertGreater(with_kev["score"], baseline["score"])
        # Score diff must reflect KEV threat contribution
        diff = with_kev["score"] - baseline["score"]
        self.assertGreaterEqual(diff, 10.0)
        self.assertIn("CISA KEV catalog", with_kev["explanation"])
        self.assertNotIn("CISA KEV catalog", baseline["explanation"])

    def test_asset_criticality_impact(self):
        """Test 6: Asset tier priority elevates the risk score."""
        low_crit = calculate_final_risk(
            cvss_score=6.0,
            cisa_kev_status=False,
            asset_criticality="LOW",
            asset_exposure="INTERNAL",
            event_severity="MEDIUM",
            attack_frequency=1,
            recency_hours_ago=10.0,
        )

        high_crit = calculate_final_risk(
            cvss_score=6.0,
            cisa_kev_status=False,
            asset_criticality="CRITICAL",
            asset_exposure="INTERNAL",
            event_severity="MEDIUM",
            attack_frequency=1,
            recency_hours_ago=10.0,
        )

        self.assertGreater(high_crit["score"], low_crit["score"])
        self.assertEqual(low_crit["factor_scores"]["Asset Criticality"], "2/15")
        self.assertEqual(high_crit["factor_scores"]["Asset Criticality"], "14/15")

    def test_repeated_attack_impact(self):
        """Test 7: Repeated attack telemetry elevates attack frequency risk."""
        single_event = calculate_final_risk(
            cvss_score=6.0,
            cisa_kev_status=False,
            asset_criticality="HIGH",
            asset_exposure="DMZ",
            event_severity="HIGH",
            attack_frequency=1,
            recency_hours_ago=2.0,
        )

        repeated_events = calculate_final_risk(
            cvss_score=6.0,
            cisa_kev_status=False,
            asset_criticality="HIGH",
            asset_exposure="DMZ",
            event_severity="HIGH",
            attack_frequency=8,
            recency_hours_ago=2.0,
        )

        self.assertGreater(repeated_events["score"], single_event["score"])
        self.assertEqual(single_event["factor_scores"]["Attack Frequency"], "2/15")
        self.assertGreaterEqual(int(repeated_events["factor_scores"]["Attack Frequency"].split("/")[0]), 10)
        self.assertIn("has repeated recent security events", repeated_events["explanation"])

    def test_missing_data_zero_fabrication(self):
        """Test 8: Missing inputs do not crash and zero-fabrication policy is enforced."""
        res = calculate_final_risk()

        self.assertIsInstance(res, dict)
        self.assertGreaterEqual(res["score"], 0.0)
        self.assertLessEqual(res["score"], 24.9)
        self.assertEqual(res["risk_level"], "LOW")
        # Factors must explicitly reflect 0 contributions on missing data
        self.assertEqual(res["factor_scores"]["CVSS"], "0/30")
        self.assertEqual(res["factor_scores"]["Known Exploited"], "0/15")
        self.assertEqual(res["factor_scores"]["Asset Criticality"], "0/15")
        self.assertEqual(res["factor_scores"]["Exposure"], "0/15")
        self.assertEqual(res["factor_scores"]["Recency"], "0/10")

    def test_individual_component_functions(self):
        """Test 9: Verifies each required component function behaves correctly."""
        # 1. Vulnerability risk
        v_res = calculate_vulnerability_risk(cvss_score=9.0)
        self.assertEqual(v_res["score"], 27.0)
        self.assertEqual(v_res["ratio"], "27/30")

        # Remediated vulnerability drops significantly
        v_rem = calculate_vulnerability_risk(cvss_score=9.0, vulnerability_status="REMEDIATED")
        self.assertLess(v_rem["score"], 5.0)

        # 2. Asset risk
        a_res = calculate_asset_risk(asset_criticality="CRITICAL")
        self.assertEqual(a_res["score"], 14.0)

        # 3. Threat risk
        t_res = calculate_threat_risk(cisa_kev_status=True, event_severity="CRITICAL")
        self.assertEqual(t_res["score"], 15.0)
        self.assertEqual(t_res["ratio"], "15/15")

        # 4. Exposure risk
        e_res = calculate_exposure_risk(asset_exposure="EXTERNAL")
        self.assertEqual(e_res["score"], 12.0)
        self.assertEqual(e_res["ratio"], "12/15")

        # 5. Frequency risk
        f_res = calculate_frequency_risk(attack_frequency=5)
        self.assertEqual(f_res["score"], 10.0)
        self.assertEqual(f_res["ratio"], "10/15")

        # 6. Recency risk
        r_res = calculate_recency_risk(hours_ago=12.0)
        self.assertEqual(r_res["score"], 8.0)
        self.assertEqual(r_res["ratio"], "8/10")

    def test_configurable_thresholds(self):
        """Test 10: Configurable risk level boundaries."""
        custom_thresholds = {
            "LOW": (0.0, 39.9),
            "MEDIUM": (40.0, 69.9),
            "HIGH": (70.0, 89.9),
            "CRITICAL": (90.0, 100.0),
        }
        # Score 72 is HIGH under default, but HIGH under custom too
        # Score 76 is CRITICAL under default, but HIGH under custom
        level_default = get_risk_level(76.0, DEFAULT_RISK_THRESHOLDS)
        level_custom = get_risk_level(76.0, custom_thresholds)

        self.assertEqual(level_default, "CRITICAL")
        self.assertEqual(level_custom, "HIGH")

    def test_risk_history_tracking_and_retrieval(self):
        """Test 11: Recording risk calculations and querying risk history over time."""
        score_data_1 = calculate_final_risk(
            cvss_score=8.5,
            cisa_kev_status=True,
            asset_criticality="CRITICAL",
            asset_exposure="EXTERNAL",
            event_severity="CRITICAL",
            attack_frequency=3,
        )

        score_data_2 = calculate_final_risk(
            cvss_score=3.0,
            cisa_kev_status=False,
            asset_criticality="LOW",
            asset_exposure="INTERNAL",
            event_severity="LOW",
            attack_frequency=1,
        )

        id1 = record_risk_history(
            score_data=score_data_1,
            asset="AST-PROD-WEB-01",
            finding="FND-20261004-001",
            timestamp="2026-10-04T01:00:00Z",
            db_path=self.db_path,
        )
        id2 = record_risk_history(
            score_data=score_data_2,
            asset="AST-INTERNAL-01",
            finding="FND-20261004-002",
            timestamp="2026-10-04T02:00:00Z",
            db_path=self.db_path,
        )

        self.assertGreater(id1, 0)
        self.assertGreater(id2, 0)

        # Retrieve all history
        history = get_risk_history(db_path=self.db_path)
        self.assertEqual(len(history), 2)
        # Check tracked fields
        record = next(r for r in history if r["finding"] == "FND-20261004-001")
        self.assertEqual(record["asset"], "AST-PROD-WEB-01")
        self.assertEqual(record["score"], score_data_1["score"])
        self.assertEqual(record["level"], score_data_1["risk_level"])
        self.assertIsInstance(record["factors"], list)
        self.assertIsInstance(record["factor_scores"], dict)

        # Filter by asset
        filtered = get_risk_history(asset="AST-PROD-WEB-01", db_path=self.db_path)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["asset"], "AST-PROD-WEB-01")

        # Trend over time
        trend = get_risk_over_time_trend(db_path=self.db_path)
        self.assertEqual(len(trend), 2)
        self.assertIn("score", trend[0])
        self.assertIn("timestamp", trend[0])


if __name__ == "__main__":
    unittest.main()
