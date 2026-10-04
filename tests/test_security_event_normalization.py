"""
Unit Tests for Security Event Normalization
Phase 2 Step 3: Verifies strict adherence to CRISP internal schema,
zero-fabrication policy, protocol parsing, and timestamp standardization.
"""

import unittest

from services.providers.security_dataset_provider import (
    normalize_security_event,
    parse_timestamp,
)


class TestSecurityEventNormalization(unittest.TestCase):
    def test_valid_cic_record_normalization(self):
        """Test 1: Normalizing fully-populated CIC-IDS2017 record."""
        raw = {
            "Flow ID": "172.16.0.1-192.168.10.50-49600-80-6",
            "Source IP": "172.16.0.1",
            "Source Port": "49600",
            "Destination IP": "192.168.10.50",
            "Destination Port": "80",
            "Protocol": "6",
            "Timestamp": "07/07/2017 01:23:45",
            "Label": "DDoS",
        }
        event = normalize_security_event(raw, dataset_source="CIC-IDS2017")

        self.assertEqual(event["event_id"], "172.16.0.1-192.168.10.50-49600-80-6")
        self.assertEqual(event["source_ip"], "172.16.0.1")
        self.assertEqual(event["destination_ip"], "192.168.10.50")
        self.assertEqual(event["source_port"], 49600)
        self.assertEqual(event["destination_port"], 80)
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual(event["timestamp"], "2017-07-07T01:23:45Z")
        self.assertEqual(event["original_attack_label"], "DDoS")
        self.assertEqual(event["crisp_attack_category"], "Denial of Service (DDoS)")
        self.assertEqual(event["severity"], "CRITICAL")
        self.assertEqual(event["dataset_source"], "CIC-IDS2017")
        self.assertEqual(event["source"], "CIC-IDS2017")

    def test_zero_fabrication_on_missing_fields(self):
        """Test 2: Zero-fabrication policy - missing values remain None, never fabricated."""
        raw = {
            "Flow ID": "FLOW-MINIMAL",
            "Label": "PortScan",
            # Source IP, Destination IP, Ports, Protocol, Timestamp are missing
        }
        event = normalize_security_event(raw)

        self.assertEqual(event["event_id"], "FLOW-MINIMAL")
        self.assertIsNone(event["source_ip"])
        self.assertIsNone(event["destination_ip"])
        self.assertIsNone(event["source_port"])
        self.assertIsNone(event["destination_port"])
        self.assertIsNone(event["protocol"])
        self.assertIsNone(event["timestamp"])
        self.assertIsNone(event["cve_id"])
        self.assertIsNone(event["asset_id"])
        # Original label preserved
        self.assertEqual(event["original_attack_label"], "PortScan")
        self.assertEqual(event["crisp_attack_category"], "Reconnaissance (Port Scan)")

    def test_protocol_mapping(self):
        """Test 3: Protocol integer conversion to standard protocol names."""
        raw_tcp = {"Flow ID": "F1", "Protocol": "6", "Label": "BENIGN"}
        raw_udp = {"Flow ID": "F2", "Protocol": "17", "Label": "BENIGN"}
        raw_icmp = {"Flow ID": "F3", "Protocol": "1", "Label": "BENIGN"}

        self.assertEqual(normalize_security_event(raw_tcp)["protocol"], "TCP")
        self.assertEqual(normalize_security_event(raw_udp)["protocol"], "UDP")
        self.assertEqual(normalize_security_event(raw_icmp)["protocol"], "ICMP")

    def test_timestamp_parsing_and_fallbacks(self):
        """Test 4: Timestamp formats parsed to ISO-8601; invalid strings yield None."""
        self.assertEqual(parse_timestamp("07/07/2017 01:23:45"), "2017-07-07T01:23:45Z")
        self.assertEqual(parse_timestamp("04/07/2017 10:15"), "2017-07-04T10:15:00Z")
        self.assertEqual(parse_timestamp("2017-07-05T09:35:12Z"), "2017-07-05T09:35:12Z")
        self.assertIsNone(parse_timestamp("not-a-timestamp"))
        self.assertIsNone(parse_timestamp(None))
        self.assertIsNone(parse_timestamp(""))

    def test_heartbleed_cve_linking(self):
        """Test 5: Explicit benchmark vulnerability linking (Heartbleed CVE-2014-0160)."""
        raw = {"Flow ID": "FLOW-HB", "Label": "Heartbleed"}
        event = normalize_security_event(raw)
        self.assertEqual(event["cve_id"], "CVE-2014-0160")
        self.assertEqual(event["crisp_attack_category"], "Exploit (Heartbleed)")
        self.assertEqual(event["severity"], "CRITICAL")

    def test_invalid_input_type(self):
        """Test 6: Passing non-dict raises ValueError."""
        with self.assertRaises(ValueError):
            normalize_security_event("not a dict")  # type: ignore


if __name__ == "__main__":
    unittest.main()
