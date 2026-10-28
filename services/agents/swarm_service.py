"""
CRISP Agent Swarm 2.0 - High-Level Swarm Service API
Provides clean invocation functions for running multi-agent investigations
and checking swarm runtime telemetry.
"""

import time
import os
import logging
from typing import Any, Dict, List, Optional

from services.agents.schemas import InvestigationState, AgentRole, AUTHORIZED_ROLES
from services.agents.graph import get_agent_swarm
from services.agents.groq_client import get_groq_client
from services.agents.langgraph_compat import HAS_NATIVE_LANGGRAPH

logger = logging.getLogger("CRISP.SwarmService")


def check_authorization(user_role: Optional[str]) -> bool:
    """Verifies that the user role is authorized to perform swarm investigations."""
    if not user_role:
        return False
    return user_role.upper() in AUTHORIZED_ROLES


def run_investigation(
    query: str,
    target_cve: Optional[str] = None,
    target_asset: Optional[str] = None,
    user_role: str = "SOC_ANALYST",
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a complete supervised multi-agent investigation across the 7 CRISP agents.
    Returns the accumulated investigation state and synthesized final report.
    """
    start_time = time.time()
    logger.info(f"Initiating CRISP Agent Swarm investigation for: '{query[:80]}'")

    # Security: Enforce authorization
    if not check_authorization(user_role):
        logger.warning(f"Unauthorized investigation attempt rejected for role: {user_role}")
        return {
            "investigation_id": f"INV-AUTH-DENIED-{int(time.time())}",
            "error": f"Unauthorized: user role '{user_role}' has insufficient permissions to perform multi-agent investigations.",
            "status": "AUTH_DENIED",
            "overall_risk_rating": "N/A",
            "overall_risk_score": 0.0,
            "executive_summary": f"Access Denied: Role '{user_role}' is not authorized to access CRISP Agent Swarm 2.0 telemetry and intelligence assets.",
            "confirmed_findings": [],
            "hypotheses": [],
            "missing_evidence": [{"item": "Authorization", "reason": f"Role '{user_role}' lacks SOC investigation privileges."}],
            "verification": {"status": "UNVERIFIED", "confidence_score": 0.0, "summary": "Investigation rejected due to unauthorized role."},
            "duration_ms": 0.0,
            "agent_success_rate": 0.0,
            "investigation_completeness": 0.0,
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "total_calls": 0},
        }

    initial_state = InvestigationState(
        query=query,
        target_cve=target_cve,
        target_asset=target_asset,
        user_role=user_role,
        tenant_id=tenant_id,
    )

    swarm = get_agent_swarm()
    final_state = swarm.invoke(initial_state)

    duration_ms = round((time.time() - start_time) * 1000, 2)
    final_state["duration_ms"] = duration_ms

    # Compute operational metrics
    active = final_state.get("active_agents") or (final_state.get("plan", {}).get("target_agents") if final_state.get("plan") else [])
    failures = final_state.get("agent_failures", [])
    total_active = max(1, len(active))
    final_state["agent_success_rate"] = round(max(0.0, (total_active - len(failures)) / total_active), 2)

    confirmed_count = len(final_state.get("confirmed_findings", []))
    missing_count = len(final_state.get("missing_evidence", []))
    total_ev = confirmed_count + missing_count
    final_state["investigation_completeness"] = round(confirmed_count / max(1, total_ev), 2) if total_ev > 0 else 0.5

    groq = get_groq_client()
    final_state["token_usage"] = groq.get_token_usage()

    logger.info(
        f"Investigation {final_state.get('investigation_id')} completed in {duration_ms}ms "
        f"with overall risk rating: {final_state.get('overall_risk_rating')} "
        f"(success_rate={final_state['agent_success_rate']}, completeness={final_state['investigation_completeness']})"
    )

    return dict(final_state)


def get_investigation_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves list of past multi-agent investigations."""
    from services.agents.tools import tool_get_investigation_history
    return tool_get_investigation_history(limit=limit)


def get_investigation_by_id(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single investigation with full report details."""
    from services.agents.tools import tool_get_investigation_by_id
    return tool_get_investigation_by_id(investigation_id=investigation_id)


def get_swarm_status() -> Dict[str, Any]:
    """Returns operational status and capabilities of the CRISP Agent Swarm."""
    groq = get_groq_client()
    return {
        "status": "OPERATIONAL",
        "version": "2.0.0",
        "architecture": "Supervised Multi-Agent LangGraph Swarm",
        "has_native_langgraph": HAS_NATIVE_LANGGRAPH,
        "groq_integration": {
            "is_configured": groq.is_configured(),
            "model": groq.model,
            "timeout_seconds": groq.timeout,
        },
        "agents": [
            {
                "role": AgentRole.ORCHESTRATOR.value,
                "name": "Orchestrator Agent",
                "description": "Plans investigations, selects agents, and combines results into executive reports.",
                "read_only": True,
            },
            {
                "role": AgentRole.THREAT_INTEL.value,
                "name": "Threat Intelligence Agent",
                "description": "Investigates security events, anomalies, and attack patterns across telemetry.",
                "read_only": True,
            },
            {
                "role": AgentRole.VULN_INTEL.value,
                "name": "Vulnerability Intelligence Agent",
                "description": "Analyzes NVD CVEs, CVSS metrics, CWE weaknesses, and CISA KEV catalog.",
                "read_only": True,
            },
            {
                "role": AgentRole.ASSET_RISK.value,
                "name": "Asset Risk Agent",
                "description": "Examines asset criticality, network exposure, and multi-factor risk scores.",
                "read_only": True,
            },
            {
                "role": AgentRole.COMPLIANCE.value,
                "name": "Compliance Agent",
                "description": "Analyzes relevant NIST CSF 2.0 functions, control evidence, and audit gaps.",
                "read_only": True,
            },
            {
                "role": AgentRole.EVIDENCE.value,
                "name": "Evidence Agent",
                "description": "Retrieves authoritative records using ChromaDB vector collections and RAG.",
                "read_only": True,
            },
            {
                "role": AgentRole.VERIFICATION.value,
                "name": "Verification Agent",
                "description": "Cross-checks evidence consistency, flags contradictions, and validates conclusions.",
                "read_only": True,
            },
            {
                "role": AgentRole.REMEDIATION.value,
                "name": "Remediation Agent",
                "description": "Analyzes verified findings, recommends authoritative vendor actions, and formulates rollback & verification procedures.",
                "read_only": True,
            },
        ],
        "safety_controls": {
            "arbitrary_shell_disabled": True,
            "arbitrary_sql_disabled": True,
            "read_only_enforced": True,
            "concurrency_enabled": True,
            "bounded_retries": True,
        },
    }


def stream_investigation(
    query: str,
    target_cve: Optional[str] = None,
    target_asset: Optional[str] = None,
    user_role: str = "SOC_ANALYST",
    on_event: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Executes the multi-agent investigation with granular, real-time event callbacks
    as each agent and stage transitions: Pending -> Running -> Completed / Failed / Skipped.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from services.agents.graph import (
        node_orchestrator_plan,
        node_evidence_refinement,
        node_verification,
        node_orchestrator_synthesize,
        node_persist_investigation,
    )
    from services.agents.specialized_agents import (
        ThreatIntelligenceAgent,
        VulnerabilityIntelligenceAgent,
        AssetRiskAgent,
        ComplianceAgent,
        EvidenceAgent,
        RemediationAgent,
    )

    def emit(ev: Dict[str, Any]):
        if on_event and callable(on_event):
            try:
                on_event(ev)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")

    # Security: Enforce authorization
    if not check_authorization(user_role):
        logger.warning(f"Unauthorized stream investigation rejected for role: {user_role}")
        auth_err = {
            "investigation_id": f"INV-AUTH-DENIED-{int(time.time())}",
            "error": f"Unauthorized: user role '{user_role}' has insufficient permissions to perform multi-agent investigations.",
            "status": "AUTH_DENIED",
            "overall_risk_rating": "N/A",
            "overall_risk_score": 0.0,
            "executive_summary": f"Access Denied: Role '{user_role}' is not authorized to access CRISP Agent Swarm 2.0 telemetry and intelligence assets.",
            "confirmed_findings": [],
            "hypotheses": [],
            "missing_evidence": [{"item": "Authorization", "reason": f"Role '{user_role}' lacks SOC investigation privileges."}],
            "verification": {"status": "UNVERIFIED", "confidence_score": 0.0, "summary": "Investigation rejected due to unauthorized role."},
            "duration_ms": 0.0,
            "agent_success_rate": 0.0,
            "investigation_completeness": 0.0,
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "total_calls": 0},
        }
        emit({"type": "error", "message": auth_err["error"], "details": auth_err})
        emit({"type": "investigation_complete", "status": "auth_denied", "final_state": auth_err})
        return auth_err

    start_time = time.time()
    state = InvestigationState(
        query=query,
        target_cve=target_cve,
        target_asset=target_asset,
        user_role=user_role,
    )

    all_agents = [
        AgentRole.ORCHESTRATOR.value,
        AgentRole.THREAT_INTEL.value,
        AgentRole.VULN_INTEL.value,
        AgentRole.ASSET_RISK.value,
        AgentRole.COMPLIANCE.value,
        AgentRole.EVIDENCE.value,
        AgentRole.REMEDIATION.value,
        AgentRole.VERIFICATION.value,
    ]

    domain_agents = [
        AgentRole.THREAT_INTEL.value,
        AgentRole.VULN_INTEL.value,
        AgentRole.ASSET_RISK.value,
        AgentRole.COMPLIANCE.value,
        AgentRole.EVIDENCE.value,
        AgentRole.REMEDIATION.value,
    ]

    # 1. Initial State Broadcast
    emit({
        "type": "init",
        "investigation_id": state["investigation_id"],
        "query": query,
        "agents": {ag: "pending" for ag in all_agents},
    })

    # 2. Stage 1: Orchestrator Planning
    emit({
        "type": "agent_status",
        "agent": AgentRole.ORCHESTRATOR.value,
        "status": "running",
        "message": "Analyzing scope and formulating investigation plan...",
    })

    plan_update = node_orchestrator_plan(state)
    state.update(plan_update)
    plan = state.get("plan", {})
    target_agents = plan.get("target_agents", domain_agents)
    skipped_agents = [ag for ag in domain_agents if ag not in target_agents]

    for ag in skipped_agents:
        emit({
            "type": "agent_status",
            "agent": ag,
            "status": "skipped",
            "message": f"Agent skipped based on orchestrator scope classification for {state.get('workflow_type')}.",
        })

    emit({
        "type": "plan_ready",
        "workflow_type": state.get("workflow_type"),
        "target_cve": state.get("target_cve"),
        "target_asset": state.get("target_asset"),
        "plan": plan,
        "target_agents": target_agents,
        "skipped_agents": skipped_agents,
    })

    emit({
        "type": "agent_status",
        "agent": AgentRole.ORCHESTRATOR.value,
        "status": "completed",
        "message": f"Investigation plan ready ({state.get('workflow_type')}). Selected {len(target_agents)} active agents.",
    })

    # 3. Stage 2: Concurrent Domain Agents
    agent_callables = {
        AgentRole.THREAT_INTEL.value: ThreatIntelligenceAgent().run,
        AgentRole.VULN_INTEL.value: VulnerabilityIntelligenceAgent().run,
        AgentRole.ASSET_RISK.value: AssetRiskAgent().run,
        AgentRole.COMPLIANCE.value: ComplianceAgent().run,
        AgentRole.EVIDENCE.value: EvidenceAgent().run,
        AgentRole.REMEDIATION.value: RemediationAgent().run,
    }

    for ag in target_agents:
        emit({
            "type": "agent_status",
            "agent": ag,
            "status": "running",
            "message": f"Executing {ag} analysis against CRISP sources...",
        })

    errors: List[Dict[str, Any]] = list(state.get("errors") or [])
    agent_failures: List[str] = list(state.get("agent_failures") or [])

    tasks = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        for agent_name in target_agents:
            if agent_name in agent_callables:
                fn = agent_callables[agent_name]
                tasks[executor.submit(fn, dict(state))] = agent_name

        for future in as_completed(tasks, timeout=16.0):
            agent_name = tasks[future]
            try:
                res = future.result(timeout=12.0)
                if isinstance(res, dict):
                    state.update(res)
                    emit({
                        "type": "agent_status",
                        "agent": agent_name,
                        "status": "completed",
                        "message": f"Agent {agent_name} successfully gathered intelligence.",
                        "result": res.get(agent_name),
                    })
            except Exception as e:
                logger.error(f"Agent '{agent_name}' failed in stream execution: {e}")
                errors.append({"agent": agent_name, "error": str(e)})
                agent_failures.append(agent_name)
                emit({
                    "type": "agent_status",
                    "agent": agent_name,
                    "status": "failed",
                    "message": f"Execution error: {str(e)}",
                    "error": str(e),
                })

    if errors:
        state["errors"] = errors
        state["agent_failures"] = agent_failures

    # 4. Stage 3: Evidence Refinement
    if plan.get("requires_evidence_refinement", False):
        emit({
            "type": "stage",
            "stage": "evidence_refinement",
            "status": "running",
            "message": "Refining evidence and querying supplementary vector embeddings...",
        })
        refine_update = node_evidence_refinement(state)
        if refine_update:
            state.update(refine_update)
        emit({
            "type": "stage",
            "stage": "evidence_refinement",
            "status": "completed",
            "message": "Evidence refinement complete.",
        })

    # 5. Stage 4: Verification Agent
    emit({
        "type": "agent_status",
        "agent": AgentRole.VERIFICATION.value,
        "status": "running",
        "message": "Cross-verifying evidence, fact claims, and contradiction checks...",
    })

    try:
        verify_update = node_verification(state)
        state.update(verify_update)
        emit({
            "type": "agent_status",
            "agent": AgentRole.VERIFICATION.value,
            "status": "completed",
            "message": "Verification completed with zero ungrounded conclusions.",
            "verification": state.get("verification"),
        })
    except Exception as e:
        logger.error(f"Verification agent error: {e}")
        emit({
            "type": "agent_status",
            "agent": AgentRole.VERIFICATION.value,
            "status": "failed",
            "error": str(e),
        })

    # 6. Stage 5: Orchestrator Synthesis
    emit({
        "type": "agent_status",
        "agent": AgentRole.ORCHESTRATOR.value,
        "status": "running",
        "message": "Synthesizing executive summary, risk calculation, and NIST mappings...",
    })

    try:
        synth_update = node_orchestrator_synthesize(state)
        state.update(synth_update)
        emit({
            "type": "agent_status",
            "agent": AgentRole.ORCHESTRATOR.value,
            "status": "completed",
            "message": "Executive synthesis and final report compiled.",
        })
    except Exception as e:
        logger.error(f"Orchestrator synthesis error: {e}")
        emit({
            "type": "agent_status",
            "agent": AgentRole.ORCHESTRATOR.value,
            "status": "failed",
            "error": str(e),
        })

    # 7. Stage 6: Persistence
    node_persist_investigation(state)

    duration_ms = round((time.time() - start_time) * 1000, 2)
    state["duration_ms"] = duration_ms

    # Compute operational metrics
    active = target_agents
    failures = state.get("agent_failures", [])
    total_active = max(1, len(active))
    state["agent_success_rate"] = round(max(0.0, (total_active - len(failures)) / total_active), 2)

    confirmed_count = len(state.get("confirmed_findings", []))
    missing_count = len(state.get("missing_evidence", []))
    total_ev = confirmed_count + missing_count
    state["investigation_completeness"] = round(confirmed_count / max(1, total_ev), 2) if total_ev > 0 else 0.5

    groq = get_groq_client()
    state["token_usage"] = groq.get_token_usage()

    final_dict = dict(state)
    emit({
        "type": "investigation_complete",
        "status": "completed",
        "investigation_id": state.get("investigation_id"),
        "duration_ms": duration_ms,
        "final_state": final_dict,
    })

    return final_dict
