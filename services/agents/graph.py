"""
CRISP Agent Swarm 2.0 - LangGraph Supervised Multi-Agent Workflow
Coordinates the Orchestrator, Threat Intel, Vuln Intel, Asset Risk,
Compliance, Evidence, and Verification agents in a supervised LangGraph state machine.
Features dynamic evidence refinement, concurrent execution of independent agents,
timeouts, bounded error handling, and auditable history persistence.
"""

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from services.agents.langgraph_compat import StateGraph, START, END
from services.agents.schemas import InvestigationState, AgentRole
from services.agents.tools import tool_rag_search, tool_persist_investigation
from services.agents.specialized_agents import (
    OrchestratorAgent,
    ThreatIntelligenceAgent,
    VulnerabilityIntelligenceAgent,
    AssetRiskAgent,
    ComplianceAgent,
    EvidenceAgent,
    VerificationAgent,
    RemediationAgent,
)

logger = logging.getLogger("CRISP.SwarmGraph")


def node_orchestrator_plan(state: InvestigationState) -> Dict[str, Any]:
    """Orchestrator step 1: Plans the investigation, classifies workflow, and selects target agents."""
    agent = OrchestratorAgent()
    return agent.plan(state)


def node_concurrent_investigation(state: InvestigationState) -> Dict[str, Any]:
    """
    Executes independent domain agents concurrently using ThreadPoolExecutor.
    Handles timeouts, partial failures, and bounded error logging.
    """
    plan = state.get("plan", {})
    target_agents = plan.get("target_agents", [
        AgentRole.THREAT_INTEL.value,
        AgentRole.VULN_INTEL.value,
        AgentRole.ASSET_RISK.value,
        AgentRole.COMPLIANCE.value,
        AgentRole.EVIDENCE.value,
        AgentRole.REMEDIATION.value,
    ])

    agent_callables = {
        AgentRole.THREAT_INTEL.value: ThreatIntelligenceAgent().run,
        AgentRole.VULN_INTEL.value: VulnerabilityIntelligenceAgent().run,
        AgentRole.ASSET_RISK.value: AssetRiskAgent().run,
        AgentRole.COMPLIANCE.value: ComplianceAgent().run,
        AgentRole.EVIDENCE.value: EvidenceAgent().run,
        AgentRole.REMEDIATION.value: RemediationAgent().run,
    }

    updates: Dict[str, Any] = {}
    errors: List[Dict[str, Any]] = list(state.get("errors") or [])
    agent_failures: List[str] = list(state.get("agent_failures") or [])

    # Run activated independent agents concurrently
    tasks = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        for agent_name in target_agents:
            if agent_name in agent_callables:
                fn = agent_callables[agent_name]
                tasks[executor.submit(fn, dict(state))] = agent_name

        for future in as_completed(tasks, timeout=14.0):
            agent_name = tasks[future]
            try:
                result = future.result(timeout=10.0)
                if isinstance(result, dict):
                    updates.update(result)
            except Exception as e:
                logger.error(f"Agent '{agent_name}' failed in concurrent execution: {e}")
                errors.append({"agent": agent_name, "error": str(e)})
                agent_failures.append(agent_name)

    if errors:
        updates["errors"] = errors
        updates["agent_failures"] = agent_failures
    return updates


def node_evidence_refinement(state: InvestigationState) -> Dict[str, Any]:
    """
    Dynamic Orchestrator Evidence Refinement:
    When initial agent runs identify newly discovered associations (e.g. asset-associated CVEs,
    event-attributed assets, or finding-mapped controls), requests supplementary evidence
    from ChromaDB before submitting to the Verification Agent.
    """
    plan = state.get("plan", {})
    if not plan.get("requires_evidence_refinement", False):
        return {}

    evidence = state.get("evidence") or {}
    docs = list(evidence.get("retrieved_documents", []))
    citations = list(evidence.get("citations", []))

    # Check for newly uncovered CVEs from asset
    asset_risk = state.get("asset_risk") or {}
    new_cves = asset_risk.get("mapped_cves", [])

    # Check for newly attributed assets from threat intel
    threat_intel = state.get("threat_intel") or {}
    new_assets = threat_intel.get("attributed_assets", [])

    supplementary_queries = []
    for cve in new_cves[:2]:
        supplementary_queries.append(f"vulnerability CISA KEV {cve}")
    for ast in new_assets[:2]:
        supplementary_queries.append(f"enterprise asset infrastructure {ast}")

    new_docs_count = 0
    for q in supplementary_queries:
        hits = tool_rag_search(query=q, n_results=2)
        for h in hits:
            doc_id = h.get("id", "")
            if not any(d.get("id") == doc_id for d in docs):
                docs.append(h)
                col = h.get("collection", "crisp_kb")
                citations.append(f"[{col.upper()}:{doc_id}] {h.get('document', '')[:120]}...")
                new_docs_count += 1

    if new_docs_count > 0:
        logger.info(f"Evidence Refinement retrieved {new_docs_count} supplementary document(s).")
        evidence["retrieved_documents"] = docs
        evidence["retrieved_documents_count"] = len(docs)
        evidence["citations"] = citations[:10]
        return {"evidence": evidence}

    return {}


def node_verification(state: InvestigationState) -> Dict[str, Any]:
    """Verification Agent: Cross-checks evidence, facts and detects contradictions."""
    agent = VerificationAgent()
    return agent.run(state)


def node_orchestrator_synthesize(state: InvestigationState) -> Dict[str, Any]:
    """Orchestrator step 2: Synthesizes final report, risk rating, and recommendations."""
    agent = OrchestratorAgent()
    return agent.synthesize(state)


def node_persist_investigation(state: InvestigationState) -> Dict[str, Any]:
    """Persists investigation state into SQLite investigation_history table."""
    try:
        success = tool_persist_investigation(state)
        return {"is_persisted": success}
    except Exception as e:
        logger.error(f"Failed to persist investigation: {e}")
        return {"is_persisted": False}


def build_crisp_agent_graph() -> Any:
    """
    Constructs and compiles the supervised multi-agent LangGraph.
    Graph topology:
    START -> orchestrator_plan -> concurrent_investigation -> evidence_refinement -> verification -> orchestrator_synthesize -> persist_investigation -> END
    """
    workflow = StateGraph(InvestigationState)

    # Add nodes
    workflow.add_node("orchestrator_plan", node_orchestrator_plan)
    workflow.add_node("concurrent_investigation", node_concurrent_investigation)
    workflow.add_node("evidence_refinement", node_evidence_refinement)
    workflow.add_node("verification", node_verification)
    workflow.add_node("orchestrator_synthesize", node_orchestrator_synthesize)
    workflow.add_node("persist_investigation", node_persist_investigation)

    # Set edges
    workflow.add_edge(START, "orchestrator_plan")
    workflow.add_edge("orchestrator_plan", "concurrent_investigation")
    workflow.add_edge("concurrent_investigation", "evidence_refinement")
    workflow.add_edge("evidence_refinement", "verification")
    workflow.add_edge("verification", "orchestrator_synthesize")
    workflow.add_edge("orchestrator_synthesize", "persist_investigation")
    workflow.add_edge("persist_investigation", END)

    return workflow.compile()


# Global compiled workflow instance
_compiled_swarm = None


def get_agent_swarm() -> Any:
    global _compiled_swarm
    if _compiled_swarm is None:
        _compiled_swarm = build_crisp_agent_graph()
    return _compiled_swarm
