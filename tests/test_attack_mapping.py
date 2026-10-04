"""
Unit Tests for Attack Label & Severity Mapping
Phase 2 Step 3: Verifies exact mapping of CIC-IDS2017 labels to CRISP internal classifications.
"""

import unittest

from services.providers.security_dataset_provider import map_attack_label


class TestAttackMapping(unittest.TestCase):
    def test_official_attack_labels(self):
        """Test 1: Verification of official CIC-IDS2017 labels and CRISP classifications."""
        test_cases = [
            ("DDoS", "Denial of Service (DDoS)", "CRITICAL", "RESPOND"),
            ("PortScan", "Reconnaissance (Port Scan)", "LOW", "DETECT"),
            ("FTP-Patator", "Brute Force (FTP)", "MEDIUM", "PROTECT"),
            ("SSH-Patator", "Brute Force (SSH)", "HIGH", "PROTECT"),
            ("DoS slowloris", "Denial of Service (Slowloris)", "HIGH", "RESPOND"),
            ("DoS Slowhttptest", "Denial of Service (SlowHTTP)", "HIGH", "RESPOND"),
            ("DoS Hulk", "Denial of Service (Hulk)", "HIGH", "RESPOND"),
            ("DoS GoldenEye", "Denial of Service (GoldenEye)", "HIGH", "RESPOND"),
            ("Heartbleed", "Exploit (Heartbleed)", "CRITICAL", "RESPOND"),
            ("Bot", "Command & Control (Botnet)", "HIGH", "DETECT"),
            ("Web Attack – Brute Force", "Web Attack (Brute Force)", "MEDIUM", "PROTECT"),
            ("Web Attack – XSS", "Web Attack (Cross-Site Scripting)", "MEDIUM", "PROTECT"),
            ("Web Attack – Sql Injection", "Web Attack (SQL Injection)", "HIGH", "PROTECT"),
            ("Infiltration", "Infiltration / Privilege Escalation", "CRITICAL", "RESPOND"),
            ("BENIGN", "Benign Network Traffic", "INFORMATIONAL", "IDENTIFY"),
        ]

        for raw_label, expected_cat, expected_sev, expected_nist in test_cases:
            res = map_attack_label(raw_label)
            self.assertEqual(res["crisp_attack_category"], expected_cat, f"Failed category for {raw_label}")
            self.assertEqual(res["severity"], expected_sev, f"Failed severity for {raw_label}")
            self.assertEqual(res["nist_function"], expected_nist, f"Failed NIST function for {raw_label}")

    def test_case_and_whitespace_insensitivity(self):
        """Test 2: Whitespace tolerance and case-insensitivity."""
        res_spaced = map_attack_label("  DDoS  ")
        self.assertEqual(res_spaced["crisp_attack_category"], "Denial of Service (DDoS)")
        self.assertEqual(res_spaced["severity"], "CRITICAL")

        res_lower = map_attack_label("portscan")
        self.assertEqual(res_lower["crisp_attack_category"], "Reconnaissance (Port Scan)")
        self.assertEqual(res_lower["severity"], "LOW")

    def test_unknown_attack_label_fallback(self):
        """Test 3: Unrecognized labels are not hallucinated; assigned External category."""
        res_unknown = map_attack_label("CustomUnknownAttack-99")
        self.assertEqual(res_unknown["crisp_attack_category"], "External (CustomUnknownAttack-99)")
        self.assertEqual(res_unknown["severity"], "MEDIUM")

    def test_null_and_empty_label(self):
        """Test 4: Null or empty strings handled gracefully."""
        self.assertEqual(map_attack_label(None)["crisp_attack_category"], "Unclassified Traffic")
        self.assertEqual(map_attack_label("")["crisp_attack_category"], "Unclassified Traffic")


if __name__ == "__main__":
    unittest.main()
