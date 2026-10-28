"""
CRISP 2.0 - Enterprise Readiness & Production Security Test Suite
Covers:
- RBAC authorization (ADMIN, SECURITY_ANALYST, VIEWER)
- Password hashing & rate limiting lockout
- Session token lifecycle, expiration & revocation
- Immutable append-only audit trail & secret sanitization
- Enterprise data adapters (Syslog RFC5424/CEF, Splunk SIEM, Tenable Nessus, CrowdStrike)
- Ingestion queue backpressure, idempotency, retry backoff & Dead-Letter Queue (DLQ)
- Database backup integrity and recovery
"""

import os
import time
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

from services.auth_service import (
    AuthService,
    hash_password,
    verify_password,
    ROLE_ADMIN,
    ROLE_SECURITY_ANALYST,
    ROLE_VIEWER,
    ROLE_PERMISSIONS,
)
from services.audit_service import (
    AuditService,
    sanitize_audit_details,
)
from services.providers.enterprise_adapters import (
    SyslogAdapter,
    SplunkSIEMAdapter,
    TenableNessusScannerAdapter,
    EndpointCloudTelemetryAdapter,
    EnterpriseIntegrationHub,
)
from services.pipeline.event_queue import (
    EventProcessingQueue,
    QueueItem,
)
from scripts.backup_db import perform_backup, compute_sha256


class TestEnterpriseReadiness(unittest.TestCase):
    """Enterprise readiness unit and integration tests."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_crisp.db")
        self.auth = AuthService(db_path=self.db_path)
        self.audit = AuditService(db_path=self.db_path)
        self.hub = EnterpriseIntegrationHub()

    def tearDown(self):
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    # =========================================================================
    # 1. Authentication & RBAC Tests
    # =========================================================================

    def test_password_hashing_and_verification(self):
        """Verifies PBKDF2-HMAC-SHA256 password hashing and constant-time verification."""
        raw_pw = "SuperSecret#2026!Secure"
        pw_hash = hash_password(raw_pw)
        self.assertTrue(pw_hash.startswith("pbkdf2_sha256$100000$"))
        self.assertTrue(verify_password(raw_pw, pw_hash))
        self.assertFalse(verify_password("WrongPassword#123", pw_hash))

    def test_default_seeded_enterprise_users(self):
        """Verifies seeded accounts for ADMIN, SECURITY_ANALYST, and VIEWER."""
        users = self.auth.list_users()
        emails = {u["email"]: u["role"] for u in users}
        self.assertIn("admin@crisp.local", emails)
        self.assertEqual(emails["admin@crisp.local"], ROLE_ADMIN)
        self.assertIn("saifkar98k@gmail.com", emails)
        self.assertEqual(emails["saifkar98k@gmail.com"], ROLE_SECURITY_ANALYST)
        self.assertIn("viewer@crisp.local", emails)
        self.assertEqual(emails["viewer@crisp.local"], ROLE_VIEWER)

    def test_rbac_least_privilege_boundaries(self):
        """Verifies least-privilege permission matrix across roles."""
        admin_perms = ROLE_PERMISSIONS[ROLE_ADMIN]
        analyst_perms = ROLE_PERMISSIONS[ROLE_SECURITY_ANALYST]
        viewer_perms = ROLE_PERMISSIONS[ROLE_VIEWER]

        self.assertIn("manage_users", admin_perms)
        self.assertNotIn("manage_users", analyst_perms)
        self.assertNotIn("manage_users", viewer_perms)

        self.assertIn("investigate_swarm", analyst_perms)
        self.assertNotIn("investigate_swarm", viewer_perms)

        self.assertIn("view_dashboards", viewer_perms)
        self.assertNotIn("create_remediations", viewer_perms)

    def test_session_lifecycle_and_revocation(self):
        """Tests successful login, session validation, and revocation on logout."""
        login_res = self.auth.authenticate("saifkar98k@gmail.com", "Crisp#Analyst2026!")
        self.assertTrue(login_res["success"])
        token = login_res["token"]
        self.assertTrue(token.startswith("crisp_tok_"))

        # Validate active session
        session = self.auth.validate_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session["role"], ROLE_SECURITY_ANALYST)

        # Logout / Revocation
        logged_out = self.auth.logout(token)
        self.assertTrue(logged_out)

        # After logout, session should be invalid
        self.assertIsNone(self.auth.validate_session(token))

    def test_login_rate_limiting_lockout(self):
        """Tests that 5 consecutive failed login attempts trigger a rate limit lockout."""
        email = "attacker@suspicious.local"
        for _ in range(5):
            res = self.auth.authenticate(email, "WrongPassword!")
            self.assertFalse(res["success"])

        # 6th attempt should be blocked with RATE_LIMITED code
        locked_res = self.auth.authenticate(email, "WrongPassword!")
        self.assertFalse(locked_res["success"])
        self.assertEqual(locked_res["code"], "RATE_LIMITED")
        self.assertIn("temporarily locked", locked_res["error"])

    # =========================================================================
    # 2. Audit Trail & Immutability Tests
    # =========================================================================

    def test_audit_log_recording_and_sanitization(self):
        """Tests append-only audit logging and sensitive credential redaction."""
        sensitive_details = {
            "action_name": "Reset Password",
            "password": "CleartextSecretValue123",
            "token": "raw_bearer_token_xyz",
            "safe_param": "target_asset_01",
        }
        sanitized = sanitize_audit_details(sensitive_details)
        self.assertEqual(sanitized["password"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["token"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["safe_param"], "target_asset_01")

        audit_id = self.audit.log_event(
            actor_id="admin@crisp.local",
            actor_role=ROLE_ADMIN,
            action="USER_CREATED",
            target_type="USER",
            target_id="USR-TEST-01",
            result="SUCCESS",
            details=sensitive_details,
        )
        self.assertTrue(audit_id.startswith("AUD-"))

        # Verify query
        logs = self.audit.query_logs(action="USER_CREATED")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["details"]["password"], "[REDACTED_SECRET]")

    def test_audit_log_immutability_enforcement(self):
        """Verifies database trigger strictly blocks modification or deletion of audit records."""
        audit_id = self.audit.log_event(
            actor_id="admin@crisp.local",
            actor_role=ROLE_ADMIN,
            action="CRITICAL_OPERATION",
            target_type="CONFIG",
            result="SUCCESS",
        )

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Attempt update -> must fail
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute("UPDATE audit_logs SET result = 'ALTERED' WHERE audit_id = ?", (audit_id,))

            # Attempt delete -> must fail
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute("DELETE FROM audit_logs WHERE audit_id = ?", (audit_id,))

    # =========================================================================
    # 3. Enterprise Telemetry Adapters Tests
    # =========================================================================

    def test_syslog_cef_normalization(self):
        """Tests parsing ArcSight CEF syslog into CRISP SecurityEvent schema."""
        adapter = SyslogAdapter()
        cef_sample = (
            "CEF:0|Fortinet|FortiGate|6.4|00001|SQL Injection Attempt|8|"
            "src=198.51.100.22 dst=10.0.4.15 spt=52341 dpt=443 proto=TCP"
        )
        is_valid, err = adapter.validate_payload(cef_sample)
        self.assertTrue(is_valid)

        norm = adapter.normalize_event(cef_sample)
        self.assertEqual(norm["source_ip"], "198.51.100.22")
        self.assertEqual(norm["destination_ip"], "10.0.4.15")
        self.assertEqual(norm["destination_port"], 443)
        self.assertEqual(norm["protocol"], "TCP")
        self.assertEqual(norm["severity"], "CRITICAL")
        self.assertEqual(norm["attack_category"], "SQL Injection Attempt")
        self.assertEqual(norm["data_source"], "SYSLOG_CEF")

    def test_splunk_siem_adapter_mock_and_normalization(self):
        """Tests Splunk HEC event normalization and unverified status badge."""
        adapter = SplunkSIEMAdapter()
        self.assertFalse(adapter.is_verified)
        self.assertIn("UNVERIFIED", adapter.verification_status)

        payload = {
            "event": {
                "action": "Kerberoasting Attack Detected",
                "src_ip": "10.0.99.14",
                "dest_ip": "10.0.4.15",
                "dest_port": 88,
                "severity": "high",
                "sid": "SPLUNK-ALERT-1002",
            }
        }
        is_valid, err = adapter.validate_payload(payload)
        self.assertTrue(is_valid)

        norm = adapter.normalize_event(payload)
        self.assertEqual(norm["source_ip"], "10.0.99.14")
        self.assertEqual(norm["severity"], "HIGH")
        self.assertEqual(norm["attack_category"], "Kerberoasting Attack Detected")
        self.assertEqual(norm["data_source"], "SPLUNK_SIEM")

    def test_tenable_nessus_scanner_adapter(self):
        """Tests Tenable Nessus vulnerability report normalization."""
        adapter = TenableNessusScannerAdapter()
        self.assertTrue(adapter.is_verified)

        record = {
            "plugin_id": "155998",
            "plugin_name": "Apache Log4j RCE",
            "cve": "CVE-2021-44228",
            "cvss3_base_score": 10.0,
            "host": "10.0.4.15",
            "port": 443,
            "risk_factor": "Critical",
        }
        norm = adapter.normalize_event(record)
        self.assertEqual(norm["cve_id"], "CVE-2021-44228")
        self.assertEqual(norm["cvss_score"], 10.0)
        self.assertEqual(norm["severity"], "CRITICAL")
        self.assertEqual(norm["data_source"], "TENABLE_NESSUS")

    def test_crowdstrike_endpoint_adapter(self):
        """Tests CrowdStrike Falcon EDR detection normalization."""
        adapter = EndpointCloudTelemetryAdapter()
        self.assertFalse(adapter.is_verified)

        alert = {
            "detection_id": "ldt:falcon-9912",
            "tactic": "Credential Dumping via Mimikatz",
            "hostname": "prod-dc-01",
            "local_ip": "10.0.4.15",
            "remote_ip": "198.51.100.77",
            "severity": "Critical",
        }
        norm = adapter.normalize_event(alert)
        self.assertEqual(norm["asset_name"], "prod-dc-01")
        self.assertEqual(norm["attack_category"], "EDR: Credential Dumping via Mimikatz")
        self.assertEqual(norm["severity"], "CRITICAL")

    # =========================================================================
    # 4. Asynchronous Queue & Backpressure Tests
    # =========================================================================

    def test_event_queue_enqueue_and_deduplication(self):
        """Tests bounded queue enqueueing and duplicate suppression."""
        q = EventProcessingQueue(capacity=10, workers=1, db_path=self.db_path)
        try:
            sample = {
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.4.15",
                "destination_port": 443,
                "attack_category": "Port Scan",
                "severity": "LOW",
                "timestamp": "2026-10-28T08:00:00Z",
            }

            # First enqueue: Accepted
            success, item_id = q.enqueue(sample, provider="test")
            self.assertTrue(success)
            self.assertTrue(item_id.startswith("EVT-Q-"))

            # Second enqueue with identical signature: Deduplicated
            success2, res2 = q.enqueue(sample, provider="test")
            self.assertTrue(success2)
            self.assertEqual(res2, "DEDUPLICATED")
        finally:
            q.stop()

    def test_event_queue_backpressure_threshold(self):
        """Tests that exceeding queue capacity triggers backpressure rejection."""
        tiny_q = EventProcessingQueue(capacity=3, workers=0, db_path=self.db_path)
        try:
            # Fill capacity (capacity = 3)
            for i in range(3):
                ev = {"source_ip": f"10.0.0.{i}", "destination_ip": "10.0.4.15", "attack_category": f"Probe-{i}", "timestamp": f"2026-10-28T08:00:0{i}Z"}
                ok, _ = tiny_q.enqueue(ev)
                self.assertTrue(ok)

            # 4th item must be rejected with QUEUE_FULL
            overflow_ev = {"source_ip": "10.0.0.99", "destination_ip": "10.0.4.15", "attack_category": "Overflow", "timestamp": "2026-10-28T08:00:99Z"}
            ok, code = tiny_q.enqueue(overflow_ev)
            self.assertFalse(ok)
            self.assertEqual(code, "QUEUE_FULL")
            self.assertEqual(tiny_q.total_backpressure_drops, 1)
        finally:
            tiny_q.stop()

    def test_dead_letter_queue_persistence(self):
        """Tests that permanently unprocessable items route to Dead-Letter Queue table."""
        q = EventProcessingQueue(capacity=5, workers=0, db_path=self.db_path)
        try:
            item = QueueItem(payload={"bad": "data"}, provider="malformed_source")
            item.retry_count = 3
            item.last_error = "Schema validation failed: missing IP fields"

            q._send_to_dlq(item)
            self.assertEqual(q.total_dlq, 1)

            dlq_records = q.list_dlq(limit=10)
            self.assertEqual(len(dlq_records), 1)
            self.assertEqual(dlq_records[0]["source_provider"], "malformed_source")
            self.assertIn("Schema validation failed", dlq_records[0]["error_message"])
        finally:
            q.stop()

    # =========================================================================
    # 5. Database Online Backup Integrity Check
    # =========================================================================

    def test_database_backup_and_checksum(self):
        """Verifies online atomic SQLite backup and SHA256 integrity verification."""
        backup_path = perform_backup()
        self.assertTrue(os.path.exists(backup_path))
        checksum = compute_sha256(backup_path)
        self.assertTrue(len(checksum) == 64)

        # Verify companion sha256 file
        meta_file = f"{backup_path}.sha256"
        self.assertTrue(os.path.exists(meta_file))
        with open(meta_file, "r") as f:
            content = f.read()
            self.assertIn(checksum, content)


if __name__ == "__main__":
    unittest.main()
