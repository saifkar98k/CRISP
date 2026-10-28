"""
CRISP Cybersecurity Platform - Unit & Integration Test Suite for Remediation Intelligence Engine
Tests covering:
1. Structured deterministic remediation plan generation from verified findings.
2. Prioritization based on CRISP risk engine, CVSS, CISA KEV, asset criticality, and exposure.
3. Authoritative vendor guidance vs. missing vendor evidence (never inventing fake commands).
4. Approval requirements for high-risk assets and high-priority plans.
5. Role-based authorization guard for lifecycle status transitions.
6. Mandatory verification requirement before marking resolved.
7. Verification failure triggering transition to REOPENED.
8. Dynamic residual risk recalculation using the CRISP risk engine upon verified remediation.
9. Explicit reopening with reason audit.
10. Duplicate remediation plan prevention.
11. Multi-Agent Swarm RemediationAgent integration.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone

from services.remediation_engine import (
    RemediationEngine,
    RemediationStatus,
    ApprovalStatus,
    RemediationPriority,
    calculate_remediation_priority,
    determine_approval_requirement,
    generate_authoritative_remediation_content,
    ROLE_SOC_ANALYST,
    ROLE_SECURITY_LEAD,
    ROLE_ADMIN,
    ROLE_READONLY,
)
from services.agents.schemas import InvestigationState, AgentRole
from services.agents.specialized_agents import RemediationAgent


class TestRemediationEngine(unittest.TestCase):
    def setUp(self):
        # Create a temporary SQLite database for isolated tests
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)

        # Initialize schema
        self.engine = RemediationEngine(db_path=self.temp_db_path)

        # Seed test tables: assets, vulnerabilities, security_findings
        with sqlite3.connect(self.temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip_address TEXT,
                    secondary_ips TEXT,
                    type TEXT,
                    criticality TEXT,
                    exposure TEXT,
                    owner TEXT,
                    department TEXT,
                    associated_cves TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    severity TEXT,
                    affected_products TEXT,
                    cwe TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    references_json TEXT,
                    is_known_exploited INTEGER DEFAULT 0,
                    kev_date_added TEXT,
                    kev_vendor_project TEXT,
                    kev_product TEXT,
                    kev_vulnerability_name TEXT,
                    kev_required_action TEXT,
                    kev_due_date TEXT,
                    data_source TEXT,
                    is_real_data INTEGER DEFAULT 1,
                    last_retrieved_at TEXT
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_findings (
                    finding_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    asset_id TEXT,
                    asset_name TEXT,
                    event_id TEXT,
                    cve_id TEXT,
                    attack_category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    known_exploited INTEGER DEFAULT 0,
                    asset_criticality TEXT,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    nist_function TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

            # Seed Test Assets
            cursor.execute(
                """
                INSERT INTO assets (id, name, ip_address, type, criticality, exposure, owner, department, associated_cves, created_at)
                VALUES
                ('AST-PROD-WEB-01', 'prod-edge-web01.internal', '10.0.4.15', 'Web Application', 'CRITICAL', 'EXTERNAL', 'Platform Eng', 'Digital Banking', 'CVE-2021-44228', '2026-10-01'),
                ('AST-DEV-TEST-02', 'dev-sandbox02.internal', '10.0.99.12', 'Endpoint', 'LOW', 'INTERNAL', 'QA Eng', 'Testing', 'CVE-2024-99999', '2026-10-01');
                """
            )

            # Seed Test Vulnerabilities (Log4j with KEV and Unknown CVE)
            cursor.execute(
                """
                INSERT INTO vulnerabilities (
                    cve_id, description, cvss_score, severity, affected_products, is_known_exploited,
                    kev_vendor_project, kev_required_action, references_json, data_source, is_real_data, last_retrieved_at
                ) VALUES (
                    'CVE-2021-44228', 'Apache Log4j2 JNDI RCE', 10.0, 'CRITICAL', '["Apache Log4j 2"]', 1,
                    'Apache Software Foundation', 'Apply vendor updates per BOD 22-01', '["https://logging.apache.org"]', 'CISA_KEV', 1, '2026-10-01'
                ), (
                    'CVE-2024-99999', 'Obscure Internal Tool Buffer Flaw', 4.5, 'MEDIUM', '["Custom Tool"]', 0,
                    NULL, NULL, '[]', 'NVD_API', 1, '2026-10-01'
                );
                """
            )

            # Seed Test Findings
            cursor.execute(
                """
                INSERT INTO security_findings (
                    finding_id, timestamp, asset_id, asset_name, cve_id, attack_category, severity,
                    cvss_score, known_exploited, asset_criticality, risk_score, risk_level, nist_function,
                    evidence_json, source, created_at
                ) VALUES (
                    'FND-LOG4J-CRIT', '2026-10-28T02:00:00Z', 'AST-PROD-WEB-01', 'prod-edge-web01.internal',
                    'CVE-2021-44228', 'Remote Code Execution', 'CRITICAL', 10.0, 1, 'CRITICAL', 88.5, 'CRITICAL', 'RESPOND',
                    '["Observed JNDI lookup string in HTTP request", "CVE-2021-44228 confirmed in CISA KEV"]',
                    'CORRELATION_ENGINE', '2026-10-28T02:00:00Z'
                ), (
                    'FND-DEV-LOW', '2026-10-28T03:00:00Z', 'AST-DEV-TEST-02', 'dev-sandbox02.internal',
                    'CVE-2024-99999', 'Benign Network Traffic', 'LOW', 4.5, 0, 'LOW', 22.0, 'LOW', 'IDENTIFY',
                    '["Port probe observed"]', 'CORRELATION_ENGINE', '2026-10-28T03:00:00Z'
                );
                """
            )
            conn.commit()

    def tearDown(self):
        try:
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
        except Exception:
            pass

    def test_plan_creation_from_finding(self):
        """Test structured creation with all 14 required fields."""
        plan = self.engine.create_plan_from_finding("FND-LOG4J-CRIT")
        self.assertIsNotNone(plan)

        # 14 required fields verification
        self.assertTrue(plan["remediation_id"].startswith("REM-"))
        self.assertEqual(plan["finding_id"], "FND-LOG4J-CRIT")
        self.assertEqual(plan["asset_id"], "AST-PROD-WEB-01")
        self.assertEqual(plan["cve_id"], "CVE-2021-44228")
        self.assertEqual(plan["current_risk_score"], 88.5)
        self.assertEqual(plan["current_severity"], "CRITICAL")
        self.assertEqual(plan["priority"], RemediationPriority.IMMEDIATE.value)
        self.assertIn("prod-edge-web01.internal", plan["summary"])
        self.assertTrue(len(plan["evidence"]) >= 1)
        self.assertTrue(len(plan["recommended_steps"]) >= 1)
        self.assertTrue(len(plan["vendor_advisories"]) >= 1)
        self.assertTrue(len(plan["verification_steps"]) >= 1)
        self.assertTrue(len(plan["rollback_considerations"]) >= 1)
        self.assertIn("prerequisites", plan["prerequisites"])
        self.assertIn("operational_impact", plan["prerequisites"])
        self.assertEqual(plan["approval_status"], ApprovalStatus.PENDING_APPROVAL.value)
        self.assertEqual(plan["remediation_status"], RemediationStatus.AWAITING_APPROVAL.value)
        self.assertIsNotNone(plan["created_at"])
        self.assertIsNotNone(plan["updated_at"])

    def test_priority_calculation_kev_immediate(self):
        """Confirm CISA KEV vulnerabilities receive IMMEDIATE priority."""
        priority = calculate_remediation_priority(
            cvss_score=6.0,
            is_known_exploited=True,
            asset_criticality="MEDIUM",
            asset_exposure="INTERNAL",
            current_risk_score=45.0,
        )
        self.assertEqual(priority, RemediationPriority.IMMEDIATE)

    def test_priority_calculation_critical_asset_high_cvss(self):
        """Confirm CVSS >= 9.0 on a CRITICAL external asset receives IMMEDIATE priority."""
        priority = calculate_remediation_priority(
            cvss_score=9.8,
            is_known_exploited=False,
            asset_criticality="CRITICAL",
            asset_exposure="EXTERNAL",
            current_risk_score=72.0,
        )
        self.assertEqual(priority, RemediationPriority.IMMEDIATE)

    def test_priority_calculation_high_and_medium(self):
        """Confirm CVSS >= 7.0 on high asset gets HIGH, and lower score gets MEDIUM/LOW."""
        high_pri = calculate_remediation_priority(
            cvss_score=7.5,
            is_known_exploited=False,
            asset_criticality="HIGH",
            asset_exposure="INTERNAL",
            current_risk_score=52.0,
        )
        self.assertEqual(high_pri, RemediationPriority.HIGH)

        med_pri = calculate_remediation_priority(
            cvss_score=5.0,
            is_known_exploited=False,
            asset_criticality="MEDIUM",
            asset_exposure="INTERNAL",
            current_risk_score=30.0,
        )
        self.assertEqual(med_pri, RemediationPriority.MEDIUM)

        low_pri = calculate_remediation_priority(
            cvss_score=2.0,
            is_known_exploited=False,
            asset_criticality="LOW",
            asset_exposure="ISOLATED",
            current_risk_score=15.0,
        )
        self.assertEqual(low_pri, RemediationPriority.LOW)

    def test_missing_vendor_evidence_clarification(self):
        """When authoritative vendor fix is unknown, state clearly that vendor confirmation is required without inventing commands."""
        finding = {
            "finding_id": "FND-UNKNOWN",
            "cve_id": "CVE-2024-00000-NONEXISTENT",
            "attack_category": "Zero-Day Anomaly",
        }
        content = generate_authoritative_remediation_content(
            cve_id="CVE-2024-00000-NONEXISTENT",
            finding=finding,
            vulnerability_details=None,
        )
        self.assertFalse(content["authoritative_fix_known"])
        self.assertIn("Vendor Confirmation Required", content["vendor"])
        self.assertTrue(any("vendor confirmation required" in s.lower() for s in content["recommended_steps"]))

    def test_approval_requirement_for_critical_assets(self):
        """Critical assets or IMMEDIATE/HIGH priority mandate PENDING_APPROVAL / AWAITING_APPROVAL."""
        app_status, rem_status = determine_approval_requirement(
            priority=RemediationPriority.IMMEDIATE,
            asset_criticality="CRITICAL",
            prerequisites=["Server restart required"],
            operational_impact="Service reboot required",
        )
        self.assertEqual(app_status, ApprovalStatus.PENDING_APPROVAL)
        self.assertEqual(rem_status, RemediationStatus.AWAITING_APPROVAL)

    def test_approval_not_required_for_low_impact(self):
        """Low-risk plans without reboot do not require formal change board approval."""
        app_status, rem_status = determine_approval_requirement(
            priority=RemediationPriority.LOW,
            asset_criticality="LOW",
            prerequisites=[],
            operational_impact="Zero operational downtime.",
        )
        self.assertEqual(app_status, ApprovalStatus.NOT_REQUIRED)
        self.assertEqual(rem_status, RemediationStatus.OPEN)

    def test_role_authorization_for_status_changes(self):
        """Test role-based authorization guard for lifecycle status transitions."""
        plan = self.engine.create_plan_from_finding("FND-DEV-LOW")
        rem_id = plan["remediation_id"]

        # READONLY role should be rejected
        with self.assertRaises(PermissionError):
            self.engine.update_status(rem_id, RemediationStatus.PLANNED.value, user_role=ROLE_READONLY)

        # SOC_ANALYST is allowed to mark PLANNED
        updated = self.engine.update_status(rem_id, RemediationStatus.PLANNED.value, user_role=ROLE_SOC_ANALYST)
        self.assertEqual(updated["remediation_status"], RemediationStatus.PLANNED.value)

        # AWAITING_APPROVAL plan cannot be started by a regular analyst if approval is required
        crit_plan = self.engine.create_plan_from_finding("FND-LOG4J-CRIT")
        crit_id = crit_plan["remediation_id"]
        with self.assertRaises(PermissionError):
            self.engine.update_status(crit_id, RemediationStatus.IN_PROGRESS.value, user_role=ROLE_SOC_ANALYST)

        # SECURITY_LEAD has authority to approve and transition to IN_PROGRESS
        lead_updated = self.engine.update_status(crit_id, RemediationStatus.IN_PROGRESS.value, user_role=ROLE_SECURITY_LEAD)
        self.assertEqual(lead_updated["remediation_status"], RemediationStatus.IN_PROGRESS.value)
        self.assertEqual(lead_updated["approval_status"], ApprovalStatus.APPROVED.value)

    def test_cannot_resolve_without_verification_evidence(self):
        """Cannot mark plan RESOLVED directly without submitting authentic verification evidence."""
        plan = self.engine.create_plan_from_finding("FND-DEV-LOW")
        rem_id = plan["remediation_id"]
        with self.assertRaises(ValueError):
            self.engine.update_status(rem_id, RemediationStatus.RESOLVED.value, user_role=ROLE_SOC_ANALYST)

    def test_verification_failure_triggers_reopened(self):
        """Submitting verification evidence indicating the vulnerability is still detected reopens the plan."""
        plan = self.engine.create_plan_from_finding("FND-DEV-LOW")
        rem_id = plan["remediation_id"]

        # Advance to in progress
        self.engine.update_status(rem_id, RemediationStatus.IN_PROGRESS.value, user_role=ROLE_SOC_ANALYST)

        # Submit failed verification
        failed_evidence = {
            "scanner_or_tool": "Nessus Vulnerability Scanner",
            "scan_id_or_version": "SCAN-20261028-001",
            "evidence_summary": "Vulnerability signature still active on port 8080.",
            "is_clean": False,
        }

        reopened_plan = self.engine.submit_verification(
            remediation_id=rem_id,
            verification_evidence=failed_evidence,
            user_role=ROLE_SOC_ANALYST,
        )
        self.assertEqual(reopened_plan["remediation_status"], RemediationStatus.REOPENED.value)
        self.assertIn("FAILED", reopened_plan["status_history"][-1]["notes"])

    def test_successful_verification_recalculates_risk(self):
        """Clean verification recalculates residual cyber risk using the existing CRISP risk engine."""
        plan = self.engine.create_plan_from_finding("FND-LOG4J-CRIT")
        rem_id = plan["remediation_id"]
        initial_risk = plan["current_risk_score"]

        # Approve and start
        self.engine.update_status(rem_id, RemediationStatus.IN_PROGRESS.value, user_role=ROLE_SECURITY_LEAD)

        # Submit clean verification
        clean_evidence = {
            "scanner_or_tool": "SBOM Audit & Nessus Agent",
            "scan_id_or_version": "log4j-core-2.17.1.jar verified",
            "evidence_summary": "Package upgraded to 2.17.1. Zero JNDI lookup vulnerabilities detected.",
            "is_clean": True,
        }

        resolved_plan = self.engine.submit_verification(
            remediation_id=rem_id,
            verification_evidence=clean_evidence,
            user_role=ROLE_SOC_ANALYST,
        )

        self.assertEqual(resolved_plan["remediation_status"], RemediationStatus.RESOLVED.value)
        self.assertIsNotNone(resolved_plan["post_remediation_risk_score"])
        self.assertIsNotNone(resolved_plan["risk_reduction"])
        # Risk must be strictly reduced post-remediation
        self.assertLess(resolved_plan["post_remediation_risk_score"], initial_risk)
        self.assertGreater(resolved_plan["risk_reduction"], 0.0)

    def test_explicit_reopening_with_reason(self):
        """Test explicit plan reopening with documented reason."""
        plan = self.engine.create_plan_from_finding("FND-DEV-LOW")
        rem_id = plan["remediation_id"]

        reopened = self.engine.reopen_plan(
            remediation_id=rem_id,
            reason="Observed regression in staging tests.",
            user_role=ROLE_SOC_ANALYST,
        )
        self.assertEqual(reopened["remediation_status"], RemediationStatus.REOPENED.value)
        self.assertIn("regression", reopened["status_history"][-1]["notes"])

    def test_duplicate_remediation_prevention(self):
        """Requesting plan creation for an already covered finding returns the existing plan."""
        plan1 = self.engine.create_plan_from_finding("FND-LOG4J-CRIT")
        plan2 = self.engine.create_plan_from_finding("FND-LOG4J-CRIT")
        self.assertEqual(plan1["remediation_id"], plan2["remediation_id"])

    def test_remediation_specialist_agent_run(self):
        """Tests RemediationAgent running against state targets and returning RemediationResult."""
        agent = RemediationAgent()
        state = InvestigationState(
            query="How do I remediate the critical Log4j vulnerability on our web server?",
            targets={"cve_ids": ["CVE-2021-44228"], "finding_ids": ["FND-LOG4J-CRIT"]},
            user_role="SOC_ANALYST",
        )

        # Patch agent to use our temp db engine
        old_engine = None
        try:
            import services.remediation_engine as rem_mod
            old_engine = rem_mod.remediation_engine
            rem_mod.remediation_engine = self.engine

            output = agent.run(state)
            self.assertIn("remediation", output)
            rem_res = output["remediation"]
            self.assertGreaterEqual(rem_res["remediation_plans_count"], 1)
            self.assertTrue(len(rem_res["recommended_actions"]) >= 1)
            self.assertTrue(len(rem_res["authoritative_advisories"]) >= 1)
        finally:
            if old_engine:
                import services.remediation_engine as rem_mod
                rem_mod.remediation_engine = old_engine


if __name__ == "__main__":
    unittest.main()
