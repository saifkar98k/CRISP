"""
CRISP Agent Swarm 2.0 - Comprehensive Workflow Integration Test Suite
Tests all 5 required investigation workflows, claim traceability, persistence,
and resilience under missing data, unavailable Groq, unavailable ChromaDB,
and single-agent failure scenarios.
"""

import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from services.agents.schemas import (
    AgentRole,
    WorkflowType,
    VerificationStatus,
    InvestigationState,
    FactualClaim,
)
from services.agents.tools import (
    tool_query_security_events,
    tool_get_correlated_findings,
    tool_list_assets,
    tool_query_vulnerabilities,
)
from services.agents.swarm_service import (
    run_investigation,
    get_investigation_history,
    get_investigation_by_id,
    get_swarm_status,
)
from services.agents.graph import build_crisp_agent_graph, node_concurrent_investigation
from services.agents.specialized_agents import extract_targets_and_workflow


class TestAgentWorkflowsAndResilience(unittest.TestCase):
    """Integration test suite for the 5 investigation workflows and resilience safeguards."""

    # =========================================================================
    # 1. Workflow 1: Asset Investigation
    # =========================================================================

    def test_workflow_1_asset_investigation(self):
        """
        Asset investigation workflow:
        Retrieves asset details, existing risk assessment, related vulnerabilities,
        relevant events, and applicable compliance evidence.
        """
        query = "Perform comprehensive risk assessment and audit on prod-edge-web01.internal"
        target_info = extract_targets_and_workflow(query)
        self.assertEqual(target_info.primary_target_type, WorkflowType.ASSET_INVESTIGATION.value)

        result = run_investigation(query=query, target_asset="AST-PROD-WEB-01")

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("workflow_type"), WorkflowType.ASSET_INVESTIGATION.value)
        self.assertIn("asset_risk", result)
        self.assertIn("vuln_intel", result)
        self.assertIn("threat_intel", result)
        self.assertIn("compliance", result)
        self.assertIn("verification", result)

        # Asset details & risk score
        asset_info = result["asset_risk"]
        self.assertGreater(len(asset_info.get("assets_analyzed", [])), 0)
        self.assertIn("calculated_risk_score", asset_info)
        self.assertIn("exposure_status", asset_info)
        self.assertIn("highest_criticality", asset_info)

        # Compliance evidence
        comp_info = result["compliance"]
        self.assertGreater(len(comp_info.get("relevant_controls", [])), 0)

        # Factual claims & verification
        ver_info = result["verification"]
        self.assertIn(ver_info.get("status"), [VerificationStatus.CONFIRMED.value, VerificationStatus.PARTIALLY_SUPPORTED.value])
        self.assertTrue(len(result.get("confirmed_findings", [])) > 0)

    # =========================================================================
    # 2. Workflow 2: CVE Investigation
    # =========================================================================

    def test_workflow_2_cve_investigation(self):
        """
        CVE investigation workflow:
        Retrieves actual CVE record, CVSS data, CISA KEV status,
        affected asset associations, and active findings.
        """
        cve_id = "CVE-2021-44228"
        query = f"Investigate exploit status and affected assets for {cve_id}"
        target_info = extract_targets_and_workflow(query)
        self.assertEqual(target_info.primary_target_type, WorkflowType.CVE_INVESTIGATION.value)

        result = run_investigation(query=query, target_cve=cve_id)

        self.assertEqual(result.get("workflow_type"), WorkflowType.CVE_INVESTIGATION.value)
        vuln_info = result["vuln_intel"]
        self.assertIn(cve_id, vuln_info.get("cves_analyzed", []))
        self.assertGreaterEqual(vuln_info.get("max_cvss_score", 0.0), 9.0)
        self.assertEqual(vuln_info.get("highest_severity"), "CRITICAL")
        self.assertTrue(len(vuln_info.get("known_exploited_matches", [])) > 0)

        # Traceability: claims must cite NVD or CISA KEV
        confirmed = result.get("confirmed_findings", [])
        has_cve_claim = any(c.get("source_id") == cve_id for c in confirmed)
        self.assertTrue(has_cve_claim, f"Expected claim with source_id={cve_id}")

    # =========================================================================
    # 3. Workflow 3: Security Event Investigation
    # =========================================================================

    def test_workflow_3_security_event_investigation(self):
        """
        Security event investigation workflow:
        Examines event evidence, timestamps, source and destination information,
        and attributes to enterprise assets where supported.
        """
        # Fetch an actual event ID from database
        events = tool_query_security_events(limit=1)
        event_id = events[0]["event_id"] if events else "SIM-CRIT-525188"

        query = f"Investigate security event {event_id} telemetry anomaly"
        target_info = extract_targets_and_workflow(query)
        self.assertEqual(target_info.primary_target_type, WorkflowType.EVENT_INVESTIGATION.value)

        result = run_investigation(query=query)

        self.assertEqual(result.get("workflow_type"), WorkflowType.EVENT_INVESTIGATION.value)
        threat_info = result["threat_intel"]
        self.assertGreater(threat_info.get("observed_events_count", 0), 0)
        self.assertIn("attack_categories", threat_info)
        self.assertIn("event_ids", threat_info)

    # =========================================================================
    # 4. Workflow 4: Critical Finding Investigation
    # =========================================================================

    def test_workflow_4_critical_finding_investigation(self):
        """
        Critical finding investigation workflow:
        Combines threat, vulnerability, asset-risk, and compliance analysis.
        """
        findings = tool_get_correlated_findings(limit=1)
        finding_id = findings[0]["finding_id"] if findings else "FND-LOG4J-01"

        query = f"Deep dive on critical security finding {finding_id}"
        target_info = extract_targets_and_workflow(query)
        self.assertEqual(target_info.primary_target_type, WorkflowType.FINDING_INVESTIGATION.value)

        result = run_investigation(query=query)

        self.assertEqual(result.get("workflow_type"), WorkflowType.FINDING_INVESTIGATION.value)
        # All domain dimensions must be populated
        self.assertIsNotNone(result.get("threat_intel"))
        self.assertIsNotNone(result.get("vuln_intel"))
        self.assertIsNotNone(result.get("asset_risk"))
        self.assertIsNotNone(result.get("compliance"))
        self.assertIsNotNone(result.get("verification"))

    # =========================================================================
    # 5. Workflow 5: General Security Question & Selective Routing
    # =========================================================================

    def test_workflow_5_general_security_question_selective_routing(self):
        """
        General security question workflow:
        Routes questions dynamically ONLY to relevant agents.
        """
        query = "Explain NIST CSF 2.0 requirements for PROTECT function controls and access enforcement"
        target_info = extract_targets_and_workflow(query)
        self.assertEqual(target_info.primary_target_type, WorkflowType.GENERAL_QUESTION.value)

        result = run_investigation(query=query)

        self.assertEqual(result.get("workflow_type"), WorkflowType.GENERAL_QUESTION.value)
        plan = result.get("plan", {})
        active_agents = plan.get("target_agents", [])

        # Compliance and Evidence must be active, but not all agents need to be forced
        self.assertIn(AgentRole.COMPLIANCE.value, active_agents)
        self.assertIn(AgentRole.EVIDENCE.value, active_agents)

    # =========================================================================
    # 6. Resilience & Fault-Tolerance Tests
    # =========================================================================

    def test_resilience_missing_data(self):
        """
        Resilience test: Missing data (non-existent asset and CVE).
        Swarm should gracefully report missing evidence without crashing.
        """
        query = "Audit non-existent asset AST-GHOST-999 and fake vulnerability CVE-1999-999999"
        result = run_investigation(query=query)

        self.assertIsInstance(result, dict)
        self.assertIn("verification", result)
        ver = result["verification"]

        # Missing evidence items should be identified
        missing = result.get("missing_evidence", [])
        self.assertTrue(len(missing) > 0, "Missing evidence items should be reported")
        self.assertIn(ver.get("status"), [VerificationStatus.UNVERIFIED.value, VerificationStatus.PARTIALLY_SUPPORTED.value])

    def test_resilience_unavailable_groq(self):
        """
        Resilience test: Unavailable Groq API.
        Swarm operates deterministically using built-in reasoning and synthesis fallbacks.
        """
        with patch.dict("os.environ", {"GROQ_API_KEY": ""}):
            result = run_investigation(query="Analyze CVE-2021-44228 without Groq key")
            self.assertIsInstance(result, dict)
            self.assertIn("executive_summary", result)
            self.assertIn("recommended_actions", result)
            self.assertTrue(len(result["recommended_actions"]) > 0)
            self.assertGreater(result["overall_risk_score"], 0.0)

    def test_resilience_unavailable_chromadb(self):
        """
        Resilience test: Unavailable or empty ChromaDB RAG.
        Swarm proceeds cleanly and marks vector evidence as missing.
        """
        with patch("services.agents.specialized_agents.tool_rag_search", return_value=[]), \
             patch("services.agents.graph.tool_rag_search", return_value=[]):
            result = run_investigation(query="Investigate CVE-2021-44228 when ChromaDB has zero hits")
            self.assertIsInstance(result, dict)
            self.assertIn("verification", result)
            # Should have recorded missing ChromaDB vector matches
            missing = result.get("missing_evidence", [])
            has_rag_missing = any("ChromaDB" in str(m) for m in missing)
            self.assertTrue(has_rag_missing)

    def test_resilience_single_agent_failure(self):
        """
        Resilience test: One agent fails unexpectedly while others succeed.
        Swarm preserves partial results from other agents and completes report.
        """
        state = InvestigationState(
            query="Test partial agent failure handling",
            workflow_type=WorkflowType.GENERAL_QUESTION.value,
        )
        state["plan"] = {
            "target_agents": [
                AgentRole.THREAT_INTEL.value,
                AgentRole.VULN_INTEL.value,
                AgentRole.ASSET_RISK.value,
            ],
            "workflow_type": WorkflowType.GENERAL_QUESTION.value,
        }

        # Mock ThreatIntel to raise an unexpected runtime error
        with patch("services.agents.specialized_agents.ThreatIntelligenceAgent.run", side_effect=RuntimeError("Simulated Telemetry DB Timeout")):
            updates = node_concurrent_investigation(state)

            # Error should be captured in errors / agent_failures
            self.assertIn("errors", updates)
            self.assertIn("agent_failures", updates)
            self.assertIn(AgentRole.THREAT_INTEL.value, updates["agent_failures"])

            # Other agents (vuln_intel, asset_risk) must have succeeded
            self.assertIn("vuln_intel", updates)
            self.assertIn("asset_risk", updates)

    # =========================================================================
    # 7. Persistence & History Verification Tests
    # =========================================================================

    def test_investigation_persistence_and_retrieval(self):
        """
        Verifies investigation is saved in SQLite investigation_history
        and retrievable via get_investigation_history and get_investigation_by_id.
        """
        query = "Test investigation persistence in SQLite database"
        result = run_investigation(query=query)
        inv_id = result.get("investigation_id")
        self.assertIsNotNone(inv_id)

        # Retrieve from history
        history = get_investigation_history(limit=10)
        self.assertIsInstance(history, list)
        self.assertTrue(any(h.get("investigation_id") == inv_id for h in history))

        # Retrieve single by ID
        record = get_investigation_by_id(inv_id)
        self.assertIsNotNone(record)
        self.assertEqual(record.get("investigation_id"), inv_id)
        self.assertIn("report", record)
        self.assertEqual(record.get("workflow_type"), result.get("workflow_type"))

    # =========================================================================
    # 8. Real-Time Streaming & Event Lifecycle Tests
    # =========================================================================

    def test_stream_investigation_events(self):
        """
        Verifies stream_investigation emits the complete sequence of granular agent events:
        init -> orchestrator planning -> plan_ready -> concurrent domain agents -> verification -> synthesis -> complete.
        """
        from services.agents.swarm_service import stream_investigation

        events = []
        result = stream_investigation(
            query="Audit asset AST-PROD-WEB-01 for vulnerabilities and risk",
            target_asset="AST-PROD-WEB-01",
            on_event=lambda ev: events.append(ev),
        )

        self.assertIsInstance(result, dict)
        self.assertIn("investigation_id", result)

        event_types = [e.get("type") for e in events]
        self.assertIn("init", event_types)
        self.assertIn("agent_status", event_types)
        self.assertIn("plan_ready", event_types)
        self.assertIn("investigation_complete", event_types)

        # Check that agent statuses transitioned through execution states
        agent_status_events = [e for e in events if e.get("type") == "agent_status"]
        self.assertTrue(any(e.get("status") == "running" for e in agent_status_events))
        self.assertTrue(any(e.get("status") == "completed" for e in agent_status_events))

    def test_stream_investigation_single_agent_failure(self):
        """
        Verifies that when one agent throws an error in streaming execution,
        that agent is marked failed, error is broadcast, and final report completes.
        """
        from services.agents.swarm_service import stream_investigation

        events = []
        with patch("services.agents.specialized_agents.ComplianceAgent.run", side_effect=RuntimeError("Audit catalog unreachable")):
            result = stream_investigation(
                query="Investigate CVE-2021-44228 across all dimensions",
                target_cve="CVE-2021-44228",
                on_event=lambda ev: events.append(ev),
            )

            self.assertIsInstance(result, dict)
            # Compliance should be noted in agent failures
            self.assertIn("compliance", result.get("agent_failures", []))

            # The compliance failure event must be emitted
            failed_events = [e for e in events if e.get("type") == "agent_status" and e.get("status") == "failed"]
            self.assertTrue(any(e.get("agent") == "compliance" for e in failed_events))

            # Final complete event must still be emitted
            self.assertTrue(any(e.get("type") == "investigation_complete" for e in events))

    def test_stream_runner_cli(self):
        """
        Verifies services.agents.stream_runner CLI correctly parses stdin and prints NDJSON events.
        """
        import subprocess
        import json

        proc = subprocess.Popen(
            ["python3", "-m", "services.agents.stream_runner"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(
            input=json.dumps({"query": "What are top CVEs?", "user_role": "SOC_ANALYST"}),
            timeout=15,
        )

        lines = [ln.strip() for ln in stdout.strip().split("\n") if ln.strip()]
        self.assertGreater(len(lines), 3)

        first_event = json.loads(lines[0])
        self.assertEqual(first_event.get("type"), "init")

        last_event = json.loads(lines[-1])
        self.assertEqual(last_event.get("type"), "investigation_complete")


if __name__ == "__main__":
    unittest.main()

