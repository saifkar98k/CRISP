"""
CRISP Agent Swarm 2.0 - Comprehensive Unit Test Suite
Validates the supervised multi-agent architecture across all 7 specialized agents,
controlled read-only tools, LangGraph workflow execution, and verification logic.
"""

import unittest
from typing import Dict, Any

from services.agents.schemas import (
    AgentRole,
    VerificationStatus,
    InvestigationState,
    InvestigationPlan,
    ThreatIntelResult,
    VulnerabilityIntelResult,
    AssetRiskResult,
    ComplianceResult,
    EvidenceResult,
    VerificationResult,
)
from services.agents.tools import (
    tool_query_security_events,
    tool_get_event_analytics,
    tool_get_correlated_findings,
    tool_query_vulnerabilities,
    tool_query_cisa_kev,
    tool_get_vulnerability_summary,
    tool_list_assets,
    tool_get_asset,
    tool_calculate_risk,
    tool_query_nist_controls,
    tool_rag_search,
)
from services.agents.specialized_agents import (
    extract_targets_from_text,
    OrchestratorAgent,
    ThreatIntelligenceAgent,
    VulnerabilityIntelligenceAgent,
    AssetRiskAgent,
    ComplianceAgent,
    EvidenceAgent,
    VerificationAgent,
)
from services.agents.graph import build_crisp_agent_graph, get_agent_swarm
from services.agents.swarm_service import run_investigation, get_swarm_status
from services.agents.groq_client import GroqClientWrapper


class TestCRISPAgentSwarm(unittest.TestCase):
    """Test suite for CRISP Agent Swarm 2.0."""

    # =========================================================================
    # 1. Target Extraction & Planning Tests
    # =========================================================================

    def test_extract_targets_from_text(self):
        query = "Analyze critical vulnerability CVE-2021-44228 and CVE-2024-3400 affecting prod-edge-web01 from IP 10.0.4.15 regarding PROTECT function with brute force"
        targets = extract_targets_from_text(query)

        self.assertIn("CVE-2021-44228", targets.cve_ids)
        self.assertIn("CVE-2024-3400", targets.cve_ids)
        self.assertTrue(any("prod-edge-web01" in a for a in targets.asset_ids))
        self.assertIn("10.0.4.15", targets.ips)
        self.assertTrue(any("brute force" in c for c in targets.attack_categories))
        self.assertIn("PROTECT", targets.nist_functions)

    def test_orchestrator_planning(self):
        state = InvestigationState(query="Investigate CVE-2021-44228 on prod-edge-web01")
        orchestrator = OrchestratorAgent()
        plan_res = orchestrator.plan(state)

        self.assertIn("plan", plan_res)
        self.assertIn("targets", plan_res)
        self.assertIn("active_agents", plan_res)
        plan = plan_res["plan"]
        self.assertIn(AgentRole.VULN_INTEL.value, plan["target_agents"])
        self.assertIn(AgentRole.THREAT_INTEL.value, plan["target_agents"])

    # =========================================================================
    # 2. Controlled Read-Only Tools Tests
    # =========================================================================

    def test_read_only_tools_bounded_and_safe(self):
        # Security events tool
        events = tool_query_security_events(limit=5)
        self.assertIsInstance(events, list)
        self.assertLessEqual(len(events), 5)

        # Event analytics tool
        analytics = tool_get_event_analytics()
        self.assertIn("by_category", analytics)
        self.assertIn("by_severity", analytics)

        # Vulnerabilities tool
        vulns = tool_query_vulnerabilities(limit=5)
        self.assertIsInstance(vulns, list)

        # KEV tool
        kevs = tool_query_cisa_kev(limit=5)
        self.assertIsInstance(kevs, list)

        # Assets tool
        assets = tool_list_assets(limit=5)
        self.assertIsInstance(assets, list)

        # NIST controls tool
        controls = tool_query_nist_controls(function="GOVERN")
        self.assertIsInstance(controls, list)
        self.assertTrue(len(controls) > 0)

        # RAG search tool
        docs = tool_rag_search("vulnerabilities", n_results=3)
        self.assertIsInstance(docs, list)

    def test_risk_calculation_tool(self):
        risk = tool_calculate_risk(
            cvss_score=9.8,
            cisa_kev_status=True,
            asset_criticality="CRITICAL",
            asset_exposure="EXTERNAL",
            event_severity="CRITICAL",
            attack_frequency=5,
        )
        self.assertIn("score", risk)
        self.assertIn("risk_level", risk)
        self.assertGreater(risk["score"], 50.0)
        self.assertIn(risk["risk_level"], ("HIGH", "CRITICAL"))

    # =========================================================================
    # 3. Individual Specialized Agents Tests
    # =========================================================================

    def test_threat_intelligence_agent(self):
        state = InvestigationState(query="Investigate brute force attacks")
        state["targets"] = extract_targets_from_text(state["query"]).to_dict()
        agent = ThreatIntelligenceAgent()
        res = agent.run(state)

        self.assertIn("threat_intel", res)
        intel = res["threat_intel"]
        self.assertIn("observed_events_count", intel)
        self.assertIn("attack_categories", intel)
        self.assertIn("summary", intel)

    def test_vulnerability_intelligence_agent(self):
        state = InvestigationState(query="Assess CVE-2021-44228 log4shell")
        state["targets"] = extract_targets_from_text(state["query"]).to_dict()
        agent = VulnerabilityIntelligenceAgent()
        res = agent.run(state)

        self.assertIn("vuln_intel", res)
        intel = res["vuln_intel"]
        self.assertIn("cves_analyzed", intel)
        self.assertIn("max_cvss_score", intel)
        self.assertIn("known_exploited_matches", intel)
        self.assertTrue(len(intel["cves_analyzed"]) > 0)

    def test_asset_risk_agent(self):
        state = InvestigationState(query="Risk evaluation for prod-edge-web01.internal")
        state["targets"] = extract_targets_from_text(state["query"]).to_dict()
        agent = AssetRiskAgent()
        res = agent.run(state)

        self.assertIn("asset_risk", res)
        asset_info = res["asset_risk"]
        self.assertIn("calculated_risk_score", asset_info)
        self.assertIn("risk_level", asset_info)
        self.assertIn("exposure_status", asset_info)

    def test_compliance_agent(self):
        state = InvestigationState(query="Compliance posture under NIST CSF IDENTIFY function")
        state["targets"] = extract_targets_from_text(state["query"]).to_dict()
        agent = ComplianceAgent()
        res = agent.run(state)

        self.assertIn("compliance", res)
        comp = res["compliance"]
        self.assertIn("affected_functions", comp)
        self.assertIn("relevant_controls", comp)
        self.assertIn("overall_compliance_score", comp)

    def test_evidence_agent(self):
        state = InvestigationState(query="Retrieve evidence for Log4Shell remote code execution")
        state["targets"] = extract_targets_from_text(state["query"]).to_dict()
        agent = EvidenceAgent()
        res = agent.run(state)

        self.assertIn("evidence", res)
        ev = res["evidence"]
        self.assertIn("retrieved_documents_count", ev)
        self.assertIn("citations", ev)

    # =========================================================================
    # 4. Verification Agent & Contradiction Detection Tests
    # =========================================================================

    def test_verification_agent_confirmed(self):
        state = InvestigationState(query="Check CVE-2021-44228")
        state["vuln_intel"] = {
            "cves_analyzed": ["CVE-2021-44228"],
            "max_cvss_score": 10.0,
            "highest_severity": "CRITICAL",
            "known_exploited_matches": [{"cve_id": "CVE-2021-44228"}],
        }
        state["asset_risk"] = {
            "assets_analyzed": ["prod-edge-web01.internal"],
            "highest_criticality": "CRITICAL",
            "exposure_status": "EXTERNAL",
        }
        state["evidence"] = {"retrieved_documents_count": 3}

        agent = VerificationAgent()
        res = agent.run(state)

        self.assertIn("verification", res)
        ver = res["verification"]
        self.assertEqual(ver["status"], VerificationStatus.CONFIRMED.value)
        self.assertGreater(ver["confidence_score"], 0.8)
        self.assertTrue(len(ver["verified_facts"]) > 0)
        self.assertEqual(len(ver["contradictions_detected"]), 0)

    def test_verification_agent_detects_contradiction(self):
        state = InvestigationState(query="Check contradiction")
        # Contradiction: Max CVSS 10.0 but claimed to be LOW severity
        state["vuln_intel"] = {
            "cves_analyzed": ["CVE-2021-44228"],
            "max_cvss_score": 10.0,
            "highest_severity": "LOW",
            "known_exploited_matches": [],
        }
        agent = VerificationAgent()
        res = agent.run(state)

        ver = res["verification"]
        self.assertEqual(ver["status"], VerificationStatus.CONTRADICTION_DETECTED.value)
        self.assertTrue(len(ver["contradictions_detected"]) > 0)

    # =========================================================================
    # 5. Full LangGraph Swarm Execution & Synthesis Tests
    # =========================================================================

    def test_full_swarm_investigation(self):
        query = "Investigate critical vulnerability CVE-2021-44228 on prod-edge-web01.internal"
        result = run_investigation(query=query)

        self.assertIsInstance(result, dict)
        self.assertIn("investigation_id", result)
        self.assertIn("execution_trace", result)
        self.assertIn("overall_risk_rating", result)
        self.assertIn("executive_summary", result)
        self.assertIn("recommended_actions", result)
        self.assertIn("verification", result)

        # Verify trace went through full supervised graph
        trace = result["execution_trace"]
        self.assertIn("orchestrator_plan", trace)
        self.assertIn("concurrent_investigation", trace)
        self.assertIn("verification", trace)
        self.assertIn("orchestrator_synthesize", trace)

        # Risk rating should be HIGH or CRITICAL for Log4Shell on edge web server
        self.assertIn(result["overall_risk_rating"], ("HIGH", "CRITICAL"))

    def test_swarm_status(self):
        status = get_swarm_status()
        self.assertEqual(status["status"], "OPERATIONAL")
        self.assertEqual(status["version"], "2.0.0")
        self.assertEqual(len(status["agents"]), 8)
        self.assertTrue(status["safety_controls"]["read_only_enforced"])
        self.assertTrue(status["safety_controls"]["arbitrary_shell_disabled"])

    def test_groq_client_wrapper_fallback(self):
        client = GroqClientWrapper(api_key="")
        self.assertFalse(client.is_configured())
        fallback_res = client.generate("System prompt", "User query")
        self.assertIn("CRISP", fallback_res)


if __name__ == "__main__":
    unittest.main()
