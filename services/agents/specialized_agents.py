"""
CRISP Agent Swarm 2.0 - Specialized Security Agents
Contains the 7 specialized read-only agents:
1. Orchestrator Agent (planning, workflow routing & synthesis)
2. Threat Intelligence Agent (security events, attack telemetry & attribution)
3. Vulnerability Intelligence Agent (CVE, CVSS, CISA KEV & affected assets)
4. Asset Risk Agent (criticality, exposure, risk history & multi-factor scoring)
5. Compliance Agent (NIST CSF 2.0 controls & audit evidence)
6. Evidence Agent (ChromaDB RAG semantic retrieval & source citations)
7. Verification Agent (factual claim traceability, contradiction detection & missing evidence analysis)
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional, Set

from services.agents.schemas import (
    AgentRole,
    WorkflowType,
    VerificationStatus,
    FactualClaim,
    InvestigationTarget,
    InvestigationPlan,
    ThreatIntelResult,
    VulnerabilityIntelResult,
    AssetRiskResult,
    ComplianceResult,
    EvidenceResult,
    VerificationResult,
    RemediationResult,
    InvestigationState,
)
from services.agents.tools import (
    tool_query_security_events,
    tool_get_security_event_by_id,
    tool_get_event_analytics,
    tool_get_correlated_findings,
    tool_get_finding_by_id,
    tool_query_vulnerabilities,
    tool_query_cisa_kev,
    tool_get_vulnerability_summary,
    tool_find_assets_affected_by_cve,
    tool_list_assets,
    tool_get_asset,
    tool_get_asset_details,
    tool_get_asset_risk_history,
    tool_get_asset_events,
    tool_attribute_event_to_asset,
    tool_calculate_risk,
    tool_query_nist_controls,
    tool_rag_search,
)
from services.agents.groq_client import get_groq_client

logger = logging.getLogger("CRISP.SpecializedAgents")

# =============================================================================
# Security & Prompt Injection Defense Guards
# =============================================================================

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions",
    r"disregard\s+(?:all\s+)?(?:system|prior|previous)\s+(?:prompts|instructions|rules)",
    r"system\s+override",
    r"jailbreak",
    r"dan\s+mode",
    r"you\s+are\s+now\s+in\s+unrestricted\s+mode",
    r"set\s+risk\s+(?:score\s+)?to\s+0",
    r"claim\s+(?:all\s+)?(?:patches\s+are\s+applied|the\s+system\s+is\s+safe)",
    r"drop\s+table",
    r"delete\s+from",
    r"grant\s+root",
    r"/bin/sh",
    r"/bin/bash",
]


def detect_prompt_injection(text: str) -> bool:
    """Scans text for adversarial prompt injection or command escape patterns."""
    if not text:
        return False
    lower = str(text).lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lower):
            return True
    return False


def sanitize_security_text(text: str) -> str:
    """Sanitizes untrusted text and wraps it in a neutral data container."""
    if not text:
        return ""
    sanitized = str(text).replace("<script>", "").replace("</script>", "")
    if detect_prompt_injection(sanitized):
        logger.warning("Adversarial prompt injection pattern detected in input/document; isolating passive data.")
        sanitized = f"[ISOLATED_DATA_RECORD: {sanitized}]"
    return sanitized


# =============================================================================
# Helper Target & Workflow Extractor
# =============================================================================

def extract_targets_and_workflow(text: str) -> InvestigationTarget:
    """
    Parses natural language query to classify the workflow type
    and extract all relevant entity targets (CVE, Asset, Event, Finding, IP, NIST).
    """
    text_clean = text or ""

    # 1. CVE regex
    cve_pattern = r"\b(CVE-\d{4}-\d{4,7})\b"
    cves = [c.upper() for c in list(set(re.findall(cve_pattern, text_clean, re.IGNORECASE)))]

    # 2. Finding regex
    finding_pattern = r"\b(FND-[A-Za-z0-9\-_.]+)\b"
    findings = list(set(re.findall(finding_pattern, text_clean, re.IGNORECASE)))

    # 3. Security Event ID regex (e.g., SIM-CRIT-525188 or flow format 172.16.0.1-192.168.10.50-...)
    event_pattern = r"\b(SIM-[A-Z0-9\-]+|(?:[0-9]{1,3}\.){3}[0-9]{1,3}-(?:[0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]+-[0-9]+-[0-9]+)\b"
    events = list(set(re.findall(event_pattern, text_clean)))

    # 4. IP regex
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ips = [ip for ip in list(set(re.findall(ip_pattern, text_clean))) if not any(ip in ev for ev in events)]

    # 5. Asset matches (ID or hostname)
    asset_ids: List[str] = []
    known_asset_identifiers = [
        "AST-PROD-WEB-01", "prod-edge-web01", "prod-edge-web01.internal",
        "AST-GW-VPN-01", "corp-vpn-gw01", "corp-vpn-gw01.internal",
        "AST-DB-FIN-01", "db-financials01", "db-financials01.internal",
        "AST-AD-DC-01", "ad-core-dc01", "ad-core-dc01.internal",
        "AST-DMZ-SSH-01", "dmz-bastion01", "dmz-bastion01.internal",
        "AST-DNS-CORE-01", "dns-core01", "dns-core01.internal",
        "AST-WS-ENG-44", "ws-engineer-laptop44", "ws-engineer-laptop44.internal",
        "AST-APP-API-01", "api-gateway01", "api-gateway01.internal",
    ]
    for an in known_asset_identifiers:
        if an.lower() in text_clean.lower():
            asset_ids.append(an)

    # 6. Attack categories
    attack_keywords = [
        "brute force", "ssh", "ftp", "ddos", "dos", "slowloris", "hulk",
        "goldeneye", "sql injection", "sqli", "xss", "cross-site scripting",
        "botnet", "infiltration", "port scan", "portscan", "reconnaissance",
        "heartbleed", "command injection", "remote code execution", "rce", "c2"
    ]
    attack_cats: List[str] = []
    for ak in attack_keywords:
        if ak in text_clean.lower():
            attack_cats.append(ak)

    # 7. NIST CSF Functions
    nist_funcs: List[str] = []
    for fn in ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]:
        if fn in text_clean.upper() or fn.lower() in text_clean.lower():
            nist_funcs.append(fn)

    # Classify Primary Workflow Type
    primary_type = WorkflowType.GENERAL_QUESTION.value
    primary_id = None

    if findings:
        primary_type = WorkflowType.FINDING_INVESTIGATION.value
        primary_id = findings[0]
    elif events or "investigate event" in text_clean.lower() or "event id" in text_clean.lower():
        primary_type = WorkflowType.EVENT_INVESTIGATION.value
        primary_id = events[0] if events else None
    elif cves or "investigate cve" in text_clean.lower() or "vulnerability analysis" in text_clean.lower():
        primary_type = WorkflowType.CVE_INVESTIGATION.value
        primary_id = cves[0] if cves else None
    elif asset_ids or "investigate asset" in text_clean.lower() or "asset audit" in text_clean.lower():
        primary_type = WorkflowType.ASSET_INVESTIGATION.value
        primary_id = asset_ids[0] if asset_ids else (ips[0] if ips else None)

    has_injection = detect_prompt_injection(text_clean)
    return InvestigationTarget(
        cve_ids=cves,
        asset_ids=list(set(asset_ids)),
        ips=ips,
        event_ids=events,
        finding_ids=findings,
        attack_categories=attack_cats,
        nist_functions=nist_funcs,
        primary_target_type=primary_type,
        primary_target_id=primary_id,
        raw_query=text_clean,
        prompt_injection_detected=has_injection,
    )


extract_targets_from_text = extract_targets_and_workflow


# =============================================================================
# 1. Orchestrator Agent (Planning & Synthesis)
# =============================================================================

class OrchestratorAgent:
    """
    Plans multi-agent investigations based on the 5 supported workflows,
    routes tasks selectively to relevant agents, coordinates evidence refinement,
    and synthesizes final explainable reports.
    """

    def __init__(self):
        self.groq = get_groq_client()

    def plan(self, state: InvestigationState) -> Dict[str, Any]:
        """Classifies inquiry into one of the 5 workflows and selects relevant agents."""
        query = state.get("query", "")
        target_cve = state.get("target_cve")
        target_asset = state.get("target_asset")

        targets = extract_targets_and_workflow(query)
        if target_cve and target_cve not in targets.cve_ids:
            targets.cve_ids.append(target_cve.upper())
            if targets.primary_target_type == WorkflowType.GENERAL_QUESTION.value:
                targets.primary_target_type = WorkflowType.CVE_INVESTIGATION.value
                targets.primary_target_id = target_cve.upper()

        if target_asset and target_asset not in targets.asset_ids:
            targets.asset_ids.append(target_asset)
            if targets.primary_target_type == WorkflowType.GENERAL_QUESTION.value:
                targets.primary_target_type = WorkflowType.ASSET_INVESTIGATION.value
                targets.primary_target_id = target_asset

        wf_type = targets.primary_target_type

        # Selective Agent Routing
        if wf_type == WorkflowType.ASSET_INVESTIGATION.value:
            # Asset investigation needs Asset Risk, Threat Intel, Vuln Intel, Compliance, Evidence
            active_agents = [
                AgentRole.ASSET_RISK.value,
                AgentRole.THREAT_INTEL.value,
                AgentRole.VULN_INTEL.value,
                AgentRole.COMPLIANCE.value,
                AgentRole.EVIDENCE.value,
            ]
            priorities = {
                AgentRole.ASSET_RISK.value: 1,
                AgentRole.THREAT_INTEL.value: 1,
                AgentRole.VULN_INTEL.value: 2,
                AgentRole.COMPLIANCE.value: 2,
                AgentRole.EVIDENCE.value: 2,
            }
            rationale = f"Workflow: Asset Investigation for target '{targets.primary_target_id}'. Examining asset inventory, risk history, active telemetry events, and mapped compliance controls."
            requires_refinement = True

        elif wf_type == WorkflowType.CVE_INVESTIGATION.value:
            # CVE investigation needs Vuln Intel, Asset Risk (affected assets), Evidence
            active_agents = [
                AgentRole.VULN_INTEL.value,
                AgentRole.ASSET_RISK.value,
                AgentRole.THREAT_INTEL.value,
                AgentRole.COMPLIANCE.value,
                AgentRole.EVIDENCE.value,
            ]
            priorities = {
                AgentRole.VULN_INTEL.value: 1,
                AgentRole.ASSET_RISK.value: 1,
                AgentRole.EVIDENCE.value: 2,
                AgentRole.THREAT_INTEL.value: 2,
                AgentRole.COMPLIANCE.value: 3,
            }
            rationale = f"Workflow: CVE Investigation for '{targets.primary_target_id}'. Analyzing NVD base score, CISA KEV weaponization status, affected asset associations, and active findings."
            requires_refinement = True

        elif wf_type == WorkflowType.EVENT_INVESTIGATION.value:
            # Event investigation needs Threat Intel, Asset Risk (attribution), Evidence
            active_agents = [
                AgentRole.THREAT_INTEL.value,
                AgentRole.ASSET_RISK.value,
                AgentRole.VULN_INTEL.value,
                AgentRole.EVIDENCE.value,
            ]
            priorities = {
                AgentRole.THREAT_INTEL.value: 1,
                AgentRole.ASSET_RISK.value: 1,
                AgentRole.EVIDENCE.value: 2,
                AgentRole.VULN_INTEL.value: 3,
            }
            rationale = f"Workflow: Security Event Investigation for '{targets.primary_target_id}'. Analyzing telemetry timestamps, packet flow, attack category, and enterprise asset attribution."
            requires_refinement = False

        elif wf_type == WorkflowType.FINDING_INVESTIGATION.value:
            # Critical Finding combines Threat, Vuln, Asset, Compliance, Evidence
            active_agents = [
                AgentRole.THREAT_INTEL.value,
                AgentRole.VULN_INTEL.value,
                AgentRole.ASSET_RISK.value,
                AgentRole.COMPLIANCE.value,
                AgentRole.EVIDENCE.value,
            ]
            priorities = {
                AgentRole.THREAT_INTEL.value: 1,
                AgentRole.VULN_INTEL.value: 1,
                AgentRole.ASSET_RISK.value: 1,
                AgentRole.COMPLIANCE.value: 2,
                AgentRole.EVIDENCE.value: 2,
            }
            rationale = f"Workflow: Critical Finding Investigation for '{targets.primary_target_id}'. Cross-correlating telemetry incident, mapped CVE, target asset exposure, and NIST CSF function."
            requires_refinement = True

        else:
            # General Question: route only to relevant agents based on query semantics
            active_agents = [AgentRole.EVIDENCE.value]
            priorities = {AgentRole.EVIDENCE.value: 1}

            q_lower = query.lower()
            if any(k in q_lower for k in ("nist", "compliance", "control", "govern", "protect", "detect", "respond", "recover", "policy", "audit")):
                active_agents.append(AgentRole.COMPLIANCE.value)
                priorities[AgentRole.COMPLIANCE.value] = 1

            if any(k in q_lower for k in ("cve", "vuln", "cvss", "kev", "cisa", "exploit", "patch", "weakness", "cwe")):
                active_agents.append(AgentRole.VULN_INTEL.value)
                priorities[AgentRole.VULN_INTEL.value] = 1

            if any(k in q_lower for k in ("event", "attack", "traffic", "telemetry", "incident", "port", "ip", "ddos", "brute force", "botnet")):
                active_agents.append(AgentRole.THREAT_INTEL.value)
                priorities[AgentRole.THREAT_INTEL.value] = 1

            if any(k in q_lower for k in ("asset", "host", "server", "risk score", "exposure", "criticality", "matrix", "perimeter")):
                active_agents.append(AgentRole.ASSET_RISK.value)
                priorities[AgentRole.ASSET_RISK.value] = 1

            # Fallback if no specific domain hit
            if len(active_agents) == 1:
                active_agents.extend([AgentRole.THREAT_INTEL.value, AgentRole.VULN_INTEL.value, AgentRole.ASSET_RISK.value])

            rationale = f"Workflow: General Security Inquiry. Dynamically routing only to relevant agents: {', '.join(active_agents)}."
            requires_refinement = False

        plan = InvestigationPlan(
            workflow_type=wf_type,
            target_agents=active_agents,
            priorities=priorities,
            rationale=rationale,
            targets=targets.to_dict(),
            requires_evidence_refinement=requires_refinement,
        )

        return {
            "workflow_type": wf_type,
            "targets": targets.to_dict(),
            "plan": plan.to_dict(),
            "active_agents": active_agents,
        }

    def synthesize(self, state: InvestigationState) -> Dict[str, Any]:
        """
        Combines outputs from all agents and verification into an executive security assessment.
        Guarantees strict separation of confirmed facts, hypotheses, and missing evidence.
        """
        query = state.get("query", "")
        wf_type = state.get("workflow_type", WorkflowType.GENERAL_QUESTION.value)
        threat = state.get("threat_intel") or {}
        vuln = state.get("vuln_intel") or {}
        asset = state.get("asset_risk") or {}
        comp = state.get("compliance") or {}
        ev = state.get("evidence") or {}
        ver = state.get("verification") or {}

        # Composite overall risk rating
        risk_score = asset.get("calculated_risk_score", 0.0)
        risk_level = asset.get("risk_level", "LOW")
        if vuln.get("known_exploited_matches") and risk_level in ("LOW", "MEDIUM"):
            risk_level = "HIGH"
        if vuln.get("max_cvss_score", 0.0) >= 9.0 and vuln.get("known_exploited_matches"):
            risk_level = "CRITICAL"

        # Citations
        citations = list(ev.get("citations", []))
        for cve in vuln.get("cves_analyzed", []):
            citations.append(f"[NVD:{cve}]")
        for a_name in asset.get("assets_analyzed", []):
            citations.append(f"[ASSET:{a_name}]")

        # Executive Summary Generation
        summary_lines = []
        summary_lines.append(f"**Investigation Target:** {query} (Workflow: `{wf_type}`)")

        if vuln.get("cves_analyzed"):
            cve_str = ", ".join(vuln["cves_analyzed"])
            kev_flag = "⚠️ **ACTIVELY WEAPONIZED IN CISA KEV**" if vuln.get("known_exploited_matches") else "No active KEV exploitation listed"
            summary_lines.append(f"• **Vulnerability Intelligence:** {cve_str} (Max CVSS: {vuln.get('max_cvss_score', 'N/A')}, Severity: {vuln.get('highest_severity', 'N/A')}) — {kev_flag}.")
            if vuln.get("affected_asset_ids"):
                summary_lines.append(f"  └ Affected enterprise asset associations: {', '.join(vuln.get('affected_asset_ids'))}")

        if threat.get("observed_events_count", 0) > 0:
            top_cats = ", ".join(threat.get("attack_categories", [])[:3])
            summary_lines.append(f"• **Threat Intelligence:** {threat.get('observed_events_count')} telemetry incident(s) analyzed. Vectors: {top_cats}.")
            if threat.get("attributed_assets"):
                summary_lines.append(f"  └ Attribution: Attack targets matched enterprise assets: {', '.join(threat.get('attributed_assets'))}")

        if asset.get("assets_analyzed"):
            a_names = ", ".join(asset.get("assets_analyzed", []))
            summary_lines.append(f"• **Asset Risk:** Targets include {a_names} (Tier: {asset.get('highest_criticality', 'N/A')}, Exposure: {asset.get('exposure_status', 'N/A')}). CRISP Multi-Factor Risk Score: **{risk_score}/100 ({risk_level})**.")

        if comp.get("affected_functions"):
            summary_lines.append(f"• **NIST CSF 2.0 Compliance:** Impact across {', '.join(comp.get('affected_functions', []))} function(s). Identified gaps: {len(comp.get('compliance_gaps', []))} control non-compliances.")

        v_status = ver.get("status", VerificationStatus.CONFIRMED.value)
        v_icon = "✅" if v_status == VerificationStatus.CONFIRMED.value else ("⚠️" if v_status == VerificationStatus.PARTIALLY_SUPPORTED.value else "❌")
        summary_lines.append(f"• **Evidence Verification:** {v_icon} Status: **{v_status}** (Confidence: {int(ver.get('confidence_score', 1.0) * 100)}%). Confirmed findings: {len(ver.get('confirmed_findings', []))}. Missing evidence: {len(ver.get('missing_evidence', []))}.")

        executive_summary = "\n".join(summary_lines)

        # Actionable recommendations
        recommendations = []
        if vuln.get("known_exploited_matches"):
            recommendations.append("Immediate emergency patch deployment required per CISA KEV binding operational directive.")
        if asset.get("exposure_status") == "EXTERNAL":
            recommendations.append("Enforce perimeter ingress filtering and virtual patching on internet-facing edge interfaces.")
        if comp.get("compliance_gaps"):
            for gap in comp.get("compliance_gaps", [])[:2]:
                recommendations.append(f"Remediate compliance deficiency in control {gap}.")
        if not recommendations:
            recommendations.append("Maintain continuous monitoring sensors and quarterly tabletop recovery exercises.")

        final_report = {
            "title": f"CRISP Security Investigation: {query[:60]}",
            "workflow_type": wf_type,
            "overall_risk_rating": risk_level,
            "overall_risk_score": risk_score,
            "executive_summary": executive_summary,
            "verification_status": v_status,
            "threat_intelligence": threat,
            "vulnerability_intelligence": vuln,
            "asset_risk": asset,
            "compliance_posture": comp,
            "evidence_citations": citations[:10],
            "confirmed_findings": ver.get("confirmed_findings", []),
            "hypotheses": ver.get("hypotheses", []),
            "missing_evidence": ver.get("missing_evidence", []),
            "recommended_actions": recommendations,
        }

        return {
            "final_report": final_report,
            "executive_summary": executive_summary,
            "recommended_actions": recommendations,
            "overall_risk_rating": risk_level,
            "overall_risk_score": risk_score,
            "confirmed_findings": ver.get("confirmed_findings", []),
            "hypotheses": ver.get("hypotheses", []),
            "missing_evidence": ver.get("missing_evidence", []),
            "citations": citations[:10],
        }


# =============================================================================
# 2. Threat Intelligence Agent (Workflow Integrated)
# =============================================================================

class ThreatIntelligenceAgent:
    """Investigates security events, telemetry anomalies, and attack attribution."""

    def run(self, state: InvestigationState) -> Dict[str, Any]:
        targets = state.get("targets", {})
        wf_type = state.get("workflow_type", WorkflowType.GENERAL_QUESTION.value)
        ips = targets.get("ips", [])
        event_ids = targets.get("event_ids", [])
        asset_ids = targets.get("asset_ids", [])

        events: List[Dict[str, Any]] = []
        attributed_assets: List[str] = []

        # 1. Event investigation workflow: Target specific event ID
        if wf_type == WorkflowType.EVENT_INVESTIGATION.value and event_ids:
            for eid in event_ids:
                ev = tool_get_security_event_by_id(eid)
                if ev:
                    events.append(ev)
                    # Attribution check
                    attr = tool_attribute_event_to_asset(ev)
                    if attr and attr.get("asset"):
                        a_name = attr["asset"].get("name", attr["asset"].get("id"))
                        attributed_assets.append(f"{a_name} ({attr.get('role', 'TARGET')})")

        # 2. Asset investigation workflow: Target events matching asset IP
        elif wf_type == WorkflowType.ASSET_INVESTIGATION.value and asset_ids:
            for aid in asset_ids:
                asset_obj = tool_get_asset_details(aid)
                if asset_obj:
                    a_ip = asset_obj.get("ip_address")
                    a_id = asset_obj.get("id")
                    evs = tool_get_asset_events(asset_ip=a_ip, asset_id=a_id, limit=30)
                    events.extend(evs)
                    attributed_assets.append(asset_obj.get("name", a_id))

        # 3. IP-specific investigation
        elif ips:
            for ip in ips[:3]:
                evs = tool_get_asset_events(asset_ip=ip, asset_id=None, limit=25)
                events.extend(evs)
                # Check attribution for this IP
                target_asset = tool_get_asset(ip_address=ip)
                if target_asset:
                    attributed_assets.append(target_asset.get("name", target_asset.get("id")))

        # 4. General query: Fetch recent telemetry
        if not events:
            attack_cats = targets.get("attack_categories") or []
            cat = attack_cats[0] if attack_cats else None
            events = tool_query_security_events(category=cat, limit=25)

        # Analytics & Correlated findings
        analytics = tool_get_event_analytics()
        correlated = tool_get_correlated_findings(limit=10)

        # Categorize
        cat_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {}
        for ev in events:
            c = ev.get("crisp_attack_category") or ev.get("threat_category") or "Unknown"
            s = ev.get("severity") or ev.get("threat_level") or "UNKNOWN"
            cat_counts[c] = cat_counts.get(c, 0) + 1
            sev_counts[s] = sev_counts.get(s, 0) + 1

        top_cats = sorted(cat_counts.keys(), key=lambda k: cat_counts[k], reverse=True)
        top_ips = analytics.get("top_source_ips", [])
        top_ips_list = [f"{item.get('source_ip')} ({item.get('attack_count')})" for item in top_ips[:5]] if isinstance(top_ips, list) and top_ips and isinstance(top_ips[0], dict) else [str(x) for x in top_ips[:5]]

        collected_event_ids = [e.get("event_id") for e in events if e.get("event_id")]

        summary = (
            f"Observed {len(events)} security telemetry event(s). "
            f"Primary attack vector(s): {', '.join(top_cats[:3]) if top_cats else 'None recorded'}. "
            f"Attributed to enterprise assets: {', '.join(attributed_assets) if attributed_assets else 'None'}. "
            f"Active correlated finding(s): {len(correlated)}."
        )

        res = ThreatIntelResult(
            observed_events_count=len(events),
            attack_categories=top_cats,
            top_source_ips=top_ips_list,
            correlated_findings=correlated[:5],
            severity_breakdown=sev_counts,
            summary=summary,
            raw_events=events[:10],
            event_ids=collected_event_ids,
            attributed_assets=attributed_assets,
        )

        return {"threat_intel": res.to_dict()}


# =============================================================================
# 3. Vulnerability Intelligence Agent (Workflow Integrated)
# =============================================================================

class VulnerabilityIntelligenceAgent:
    """Analyzes NVD CVEs, CVSS metrics, CWE weaknesses, CISA KEV and affected assets."""

    def run(self, state: InvestigationState) -> Dict[str, Any]:
        targets = state.get("targets", {})
        wf_type = state.get("workflow_type", WorkflowType.GENERAL_QUESTION.value)
        target_cves = list(targets.get("cve_ids", []))
        asset_ids = targets.get("asset_ids", [])

        # In Asset Investigation workflow: look up CVEs associated with the asset
        if wf_type == WorkflowType.ASSET_INVESTIGATION.value and asset_ids:
            for aid in asset_ids:
                asset_obj = tool_get_asset_details(aid)
                if asset_obj and asset_obj.get("associated_cves"):
                    cve_list = [c.strip() for c in asset_obj["associated_cves"].split(",") if c.strip()]
                    for c in cve_list:
                        if c not in target_cves:
                            target_cves.append(c)

        analyzed_cves: List[str] = []
        details: List[Dict[str, Any]] = []
        kev_matches: List[Dict[str, Any]] = []
        affected_asset_ids: List[str] = []
        source_refs: List[str] = []
        max_cvss = 0.0
        highest_sev = "LOW"
        affected_prods: Set[str] = set()

        if target_cves:
            for cve in target_cves:
                info = tool_get_vulnerability_summary(cve)
                if info:
                    cid = info.get("id") or info.get("cve_id") or cve
                    analyzed_cves.append(cid)
                    details.append(info)
                    cvss = float(info.get("cvss_score") or 0.0)
                    if cvss > max_cvss:
                        max_cvss = cvss
                    sev = (info.get("severity") or "LOW").upper()
                    if sev == "CRITICAL" or (sev == "HIGH" and highest_sev != "CRITICAL"):
                        highest_sev = sev
                    if info.get("is_known_exploited"):
                        kev_matches.append(info)
                    for p in info.get("affected_products", []):
                        if isinstance(p, str):
                            affected_prods.add(p)
                    for ref in info.get("references", []):
                        if isinstance(ref, str):
                            source_refs.append(ref)

                # Search affected enterprise assets
                affected_assets = tool_find_assets_affected_by_cve(cve)
                for a in affected_assets:
                    a_name = a.get("name") or a.get("id")
                    if a_name and a_name not in affected_asset_ids:
                        affected_asset_ids.append(a_name)
        else:
            # Query top recent vulnerabilities and KEV records
            vulns = tool_query_vulnerabilities(severity="CRITICAL", limit=5)
            for v in vulns:
                cve_code = v.get("cve_id") or v.get("id")
                if cve_code:
                    analyzed_cves.append(str(cve_code))
                details.append(v)
                cvss = float(v.get("cvss_score") or 0.0)
                if cvss > max_cvss:
                    max_cvss = cvss
                if v.get("is_known_exploited"):
                    kev_matches.append(v)
            if not highest_sev or highest_sev == "LOW":
                highest_sev = "HIGH" if max_cvss >= 7.0 else "MEDIUM"

        valid_cve_names = [str(c) for c in analyzed_cves if c]
        summary = (
            f"Analyzed {len(valid_cve_names)} CVE(s): {', '.join(valid_cve_names[:4])}. "
            f"Max CVSS: {max_cvss} ({highest_sev}). "
            f"CISA KEV weaponization matches: {len(kev_matches)}. "
            f"Enterprise assets mapped: {', '.join(affected_asset_ids) if affected_asset_ids else 'None directly mapped'}."
        )

        res = VulnerabilityIntelResult(
            cves_analyzed=valid_cve_names,
            known_exploited_matches=kev_matches,
            max_cvss_score=max_cvss,
            highest_severity=highest_sev,
            affected_products=list(affected_prods)[:5],
            summary=summary,
            details=details,
            affected_asset_ids=affected_asset_ids,
            source_references=source_refs,
        )

        return {
            "vuln_intel": res.to_dict(),
            "vulnerability_intel": res.to_dict(),
        }


# =============================================================================
# 4. Asset Risk Agent (Workflow Integrated)
# =============================================================================

class AssetRiskAgent:
    """Examines asset criticality, network exposure, risk history, and multi-factor scores."""

    def run(self, state: InvestigationState) -> Dict[str, Any]:
        targets = state.get("targets", {})
        wf_type = state.get("workflow_type", WorkflowType.GENERAL_QUESTION.value)
        target_assets = list(targets.get("asset_ids", []))
        ips = targets.get("ips", [])

        vuln_intel = state.get("vuln_intel") or {}
        max_cvss = vuln_intel.get("max_cvss_score", 7.5)
        is_kev = bool(vuln_intel.get("known_exploited_matches"))

        analyzed_assets: List[Dict[str, Any]] = []
        historical_assessments: List[Dict[str, Any]] = []
        mapped_cves: List[str] = []
        highest_crit = "MEDIUM"
        exposure = "INTERNAL"

        # Resolve assets
        if target_assets:
            for a_key in target_assets:
                asset_obj = tool_get_asset_details(a_key)
                if asset_obj:
                    analyzed_assets.append(asset_obj)
                    hist = tool_get_asset_risk_history(asset_obj.get("name", a_key))
                    historical_assessments.extend(hist)
                    if asset_obj.get("associated_cves"):
                        for c in asset_obj["associated_cves"].split(","):
                            c_clean = c.strip()
                            if c_clean and c_clean not in mapped_cves:
                                mapped_cves.append(c_clean)
        elif ips:
            for ip in ips:
                asset_obj = tool_get_asset(ip_address=ip)
                if asset_obj:
                    analyzed_assets.append(asset_obj)
                    hist = tool_get_asset_risk_history(asset_obj.get("name", asset_obj.get("id")))
                    historical_assessments.extend(hist)

        # Fallback to general asset sample if not target-specific
        if not analyzed_assets:
            analyzed_assets = tool_list_assets(limit=5)

        for a in analyzed_assets:
            c = (a.get("criticality") or "").upper()
            if "CRITICAL" in c:
                highest_crit = "CRITICAL"
            elif "HIGH" in c and highest_crit != "CRITICAL":
                highest_crit = "HIGH"

            exp = (a.get("network_exposure") or a.get("exposure") or "").upper()
            if "EXTERNAL" in exp or "PUBLIC" in exp or "EDGE" in exp:
                exposure = "EXTERNAL"
            elif "DMZ" in exp and exposure != "EXTERNAL":
                exposure = "DMZ"

        # Calculate explainable CRISP risk score
        risk_calc = tool_calculate_risk(
            cvss_score=max_cvss if max_cvss > 0 else 7.5,
            cisa_kev_status=is_kev,
            asset_criticality=highest_crit,
            asset_exposure=exposure,
            event_severity="HIGH" if is_kev else "MEDIUM",
            attack_frequency=3 if is_kev else 1,
            vuln_status="OPEN",
            exploit_available=is_kev,
            patch_available=True,
        )

        score = float(risk_calc.get("score") or 0.0)
        risk_level = risk_calc.get("risk_level", "MEDIUM")

        asset_names: List[str] = []
        for a in analyzed_assets:
            aid = a.get("id")
            aname = a.get("name")
            if aid and aid not in asset_names:
                asset_names.append(aid)
            if aname and aname not in asset_names:
                asset_names.append(aname)

        summary = (
            f"Assessed {len(analyzed_assets)} asset(s): {', '.join(asset_names[:4])}. "
            f"Criticality tier: {highest_crit}, Exposure: {exposure}. "
            f"Historical risk assessments on file: {len(historical_assessments)}. "
            f"CRISP Multi-Factor Risk Score: {score}/100 ({risk_level})."
        )

        res = AssetRiskResult(
            assets_analyzed=asset_names,
            highest_criticality=highest_crit,
            calculated_risk_score=score,
            risk_level=risk_level,
            factor_breakdown=risk_calc.get("factor_scores") or {},
            exposure_status=exposure,
            summary=summary,
            asset_details=analyzed_assets,
            mapped_cves=mapped_cves,
            historical_risk_assessments=historical_assessments,
        )

        return {"asset_risk": res.to_dict()}


# =============================================================================
# 5. Compliance Agent (Workflow Integrated)
# =============================================================================

class ComplianceAgent:
    """Analyzes relevant NIST CSF 2.0 functions, control evidence, and audit gaps."""

    def run(self, state: InvestigationState) -> Dict[str, Any]:
        targets = state.get("targets", {})
        wf_type = state.get("workflow_type", WorkflowType.GENERAL_QUESTION.value)
        nist_funcs = list(targets.get("nist_functions", []))

        # In Finding Investigation workflow: check the finding's mapped nist_function
        finding_ids = targets.get("finding_ids") or []
        finding_id = finding_ids[0] if finding_ids else None
        if finding_id:
            f_record = tool_get_finding_by_id(finding_id)
            if f_record and f_record.get("nist_function"):
                f_fn = f_record["nist_function"].upper()
                if f_fn not in nist_funcs:
                    nist_funcs.append(f_fn)

        controls = tool_query_nist_controls()
        relevant_controls: List[Dict[str, Any]] = []
        gaps: List[str] = []
        priorities: List[str] = []
        control_evidence: Dict[str, str] = {}

        target_funcs_set = set(f.upper() for f in nist_funcs) if nist_funcs else set()

        for c in controls:
            fn = (c.get("function") or "").upper()
            status = (c.get("status") or "").upper()
            cid = c.get("id", "UNKNOWN")

            if not target_funcs_set or fn in target_funcs_set:
                relevant_controls.append(c)
                if c.get("evidence"):
                    control_evidence[cid] = c.get("evidence")
                if status in ("NON_COMPLIANT", "PARTIAL"):
                    findings_text = c.get("findings", "Deficiency noted")
                    gaps.append(f"{cid} ({fn}): {findings_text}")
                    if c.get("required_remediation"):
                        priorities.append(f"{cid} - {c.get('required_remediation')}")

        if not relevant_controls:
            relevant_controls = controls[:5]

        affected_functions = list(set((c.get("function") or "").upper() for c in relevant_controls))
        avg_score = 80.0
        if relevant_controls:
            scores = [float(c.get("score") or 70.0) for c in relevant_controls]
            avg_score = round(sum(scores) / len(scores), 1)

        summary = (
            f"Evaluated {len(relevant_controls)} NIST CSF 2.0 control(s) across "
            f"{', '.join(affected_functions)}. Identified {len(gaps)} compliance gap(s). "
            f"Maturity score: {avg_score}%. Control evidence documented: {len(control_evidence)} item(s)."
        )

        res = ComplianceResult(
            affected_functions=affected_functions,
            relevant_controls=relevant_controls[:6],
            compliance_gaps=gaps,
            remediation_priorities=priorities[:3],
            overall_compliance_score=avg_score,
            summary=summary,
            control_evidence=control_evidence,
        )

        return {"compliance": res.to_dict()}


# =============================================================================
# 6. Evidence Agent (Workflow Integrated)
# =============================================================================

class EvidenceAgent:
    """Retrieves authoritative records using ChromaDB vector collections and RAG."""

    def run(self, state: InvestigationState) -> Dict[str, Any]:
        query = state.get("query", "")
        targets = state.get("targets", {})

        queries = [query]
        for cve in targets.get("cve_ids", [])[:2]:
            queries.append(f"vulnerability intelligence {cve}")
        for asset in targets.get("asset_ids", [])[:2]:
            queries.append(f"enterprise asset infrastructure {asset}")
        for ev_id in targets.get("event_ids", [])[:2]:
            queries.append(f"security telemetry event {ev_id}")

        all_docs: List[Dict[str, Any]] = []
        citations: List[str] = []
        collections_seen: Set[str] = set()

        for q in queries:
            hits = tool_rag_search(query=q, n_results=3)
            for h in hits:
                doc_id = h.get("id", "")
                if not any(d.get("id") == doc_id for d in all_docs):
                    all_docs.append(h)
                    col = h.get("collection", "crisp_kb")
                    collections_seen.add(col)
                    citations.append(f"[{col.upper()}:{doc_id}] {h.get('document', '')[:120]}...")

        avg_rel = 0.0
        if all_docs:
            scores = [float(d.get("similarity_score") or d.get("similarity") or 0.5) for d in all_docs]
            avg_rel = round(sum(scores) / len(scores), 4)

        summary = (
            f"Retrieved {len(all_docs)} authoritative evidence document(s) from ChromaDB "
            f"collections: {', '.join(collections_seen)}. Mean similarity: {avg_rel}."
        )

        res = EvidenceResult(
            retrieved_documents=all_docs,
            collections_searched=list(collections_seen),
            citations=citations[:5],
            avg_relevance_score=avg_rel,
            summary=summary,
        )

        return {"evidence": res.to_dict()}


# =============================================================================
# 7. Verification Agent (Rigorous Factual Claim Traceability)
# =============================================================================

class VerificationAgent:
    """
    Checks evidence, detects contradictions, and rigorously separates
    confirmed factual claims, hypotheses, and missing evidence.
    Ensures every claim is traceable to actual database records or source documents.
    """

    def run(self, state: InvestigationState) -> Dict[str, Any]:
        threat = state.get("threat_intel") or {}
        vuln = state.get("vuln_intel") or {}
        asset = state.get("asset_risk") or {}
        comp = state.get("compliance") or {}
        ev = state.get("evidence") or {}

        confirmed_findings: List[Dict[str, Any]] = []
        hypotheses: List[Dict[str, Any]] = []
        missing_evidence: List[Dict[str, Any]] = []
        contradictions: List[str] = []
        verified_facts: List[str] = []
        unverified_claims: List[str] = []

        wf_type = state.get("workflow_type", WorkflowType.GENERAL_QUESTION.value)
        targets = state.get("targets", {})

        # 0. Prompt Injection Defense Check
        if targets.get("prompt_injection_detected") or detect_prompt_injection(state.get("query", "")):
            missing_evidence.append({
                "item": "Adversarial Prompt Injection Attempt Neutralized",
                "reason": "Input contained adversarial override instructions attempting to manipulate risk rating or command execution. Instructions disregarded per CRISP safety boundary."
            })
            unverified_claims.append("Adversarial prompt injection instructions were neutralized and excluded from analysis.")

        # Read-Only Safety Bound
        verified_facts.append("No automated remediation executed. CRISP agents operate in strictly read-only advisory mode.")

        # 1. Verify Vulnerabilities & CVSS against SQLite catalog
        cves = vuln.get("cves_analyzed", [])
        if cves:
            for cve in cves:
                verified_facts.append(f"Vulnerability {cve} confirmed in NVD catalog.")
                confirmed_findings.append({
                    "claim": f"Vulnerability {cve} cataloged in NVD with severity {vuln.get('highest_severity')}.",
                    "source_type": "NVD_CATALOG",
                    "source_id": cve,
                    "source_table": "vulnerabilities",
                    "source_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    "is_verified": True,
                })
            if vuln.get("known_exploited_matches"):
                for km in vuln["known_exploited_matches"]:
                    k_id = km.get("cve_id") or km.get("id")
                    due = km.get("cisa_due_date", "Pending")
                    verified_facts.append(f"CISA KEV weaponization confirmed for {k_id} (Remediation Due: {due}).")
                    confirmed_findings.append({
                        "claim": f"{k_id} is actively weaponized in the wild per CISA KEV (Due: {due}).",
                        "source_type": "CISA_KEV_FEED",
                        "source_id": k_id,
                        "source_table": "vulnerabilities",
                        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        "is_verified": True,
                    })
            else:
                max_cvss_val = vuln.get("max_cvss_score", 0.0)
                if max_cvss_val >= 7.0:
                    verified_facts.append(f"Vulnerability {cves[0]} has high CVSS {max_cvss_val} with no confirmed CISA KEV exploitation.")
        elif wf_type in (WorkflowType.CVE_INVESTIGATION.value, WorkflowType.FINDING_INVESTIGATION.value) or targets.get("cve_ids"):
            missing_evidence.append({
                "item": "CVE Association",
                "reason": "No specific CVE identifier linked in telemetry or query."
            })
            unverified_claims.append("No specific CVE mapped.")

        # 2. Check CVSS consistency vs Severity & Contradictions
        max_cvss = vuln.get("max_cvss_score", 0.0)
        highest_sev = (vuln.get("highest_severity") or "").upper()
        if max_cvss >= 9.0 and highest_sev in ("LOW", "INFO", "MEDIUM"):
            contradictions.append(f"Contradiction: Max CVSS {max_cvss} (Critical) conflicts with assigned severity '{highest_sev}'.")
        elif max_cvss >= 9.0 and highest_sev not in ("CRITICAL", "HIGH"):
            contradictions.append(f"Contradiction: Max CVSS {max_cvss} but severity marked '{highest_sev}'.")
        elif max_cvss > 0.0:
            verified_facts.append(f"CVSS score {max_cvss} conforms to severity classification '{highest_sev}'.")

        # KEV vs Severity Contradiction Check
        if vuln.get("known_exploited_matches") and highest_sev in ("LOW", "INFO"):
            contradictions.append("Contradiction: Vulnerability is actively exploited in CISA KEV, but designated as LOW severity.")

        # 3. Verify Asset Details & Criticality
        assets = asset.get("assets_analyzed", [])
        if assets:
            for a_name in assets:
                crit = asset.get("highest_criticality", "UNKNOWN")
                exp = asset.get("exposure_status", "UNKNOWN")
                verified_facts.append(f"Asset '{a_name}' verified in inventory (Tier: {crit}, Exposure: {exp}).")
                confirmed_findings.append({
                    "claim": f"Asset {a_name} registered as Tier {crit} with {exp} network exposure.",
                    "source_type": "DATABASE_RECORD",
                    "source_id": a_name,
                    "source_table": "assets",
                    "source_url": None,
                    "is_verified": True,
                })
        elif wf_type in (WorkflowType.ASSET_INVESTIGATION.value, WorkflowType.FINDING_INVESTIGATION.value) or targets.get("asset_ids"):
            missing_evidence.append({
                "item": "Asset Registry Association",
                "reason": "No specific enterprise asset identified for this target."
            })

        # Check for unmapped IP attribution
        for ip in targets.get("ips", []):
            if not tool_get_asset(ip_address=ip):
                missing_evidence.append({
                    "item": f"Asset Attribution: {ip}",
                    "reason": f"IP address '{ip}' is not attributed to any known enterprise asset in CRISP inventory.",
                })
                unverified_claims.append(f"Entity at IP {ip} is unmapped in asset inventory.")

        # 4. Verify Telemetry & Security Events
        event_count = threat.get("observed_events_count", 0)
        if event_count > 0:
            top_cats = ", ".join(threat.get("attack_categories", [])[:3])
            verified_facts.append(f"Verified {event_count} telemetry event(s) recorded under: {top_cats}.")
            for eid in threat.get("event_ids", [])[:3]:
                confirmed_findings.append({
                    "claim": f"Telemetry event {eid} recorded in security_events store.",
                    "source_type": "DATABASE_RECORD",
                    "source_id": eid,
                    "source_table": "security_events",
                    "source_url": None,
                    "is_verified": True,
                })
        elif wf_type in (WorkflowType.EVENT_INVESTIGATION.value, WorkflowType.FINDING_INVESTIGATION.value) or targets.get("event_ids"):
            missing_evidence.append({
                "item": "Telemetry Events",
                "reason": "Zero active security telemetry events observed for this specific scope."
            })

        # 5. Distinguish Hypotheses (e.g. calculated risk score model)
        if asset.get("calculated_risk_score") is not None:
            r_score = asset.get("calculated_risk_score", 0.0)
            r_level = asset.get("risk_level", "LOW")
            hypotheses.append({
                "hypothesis": f"Derived CRISP Multi-Factor Risk Score: {r_score}/100 ({r_level}).",
                "basis": "Algorithmic synthesis of CVSS (30%), KEV (15%), Criticality (15%), Exposure (15%), Frequency (15%), and Recency (10%). NOT an official NIST formula.",
            })

        # 6. Check RAG Evidence corroboration
        ev_count = ev.get("retrieved_documents_count", 0)
        if ev_count > 0:
            verified_facts.append(f"Corroborated by {ev_count} ChromaDB knowledge base document(s).")
        elif ev or state.get("evidence"):
            missing_evidence.append({
                "item": "ChromaDB Vector Matches",
                "reason": "ChromaDB vector retriever returned zero hits above similarity threshold."
            })

        # 7. Deduplicate and validate source references
        deduped_confirmed = []
        seen_findings = set()
        for f in confirmed_findings:
            s_type = f.get("source_type")
            s_id = str(f.get("source_id") or "")
            claim_text = f.get("claim")

            # Validate source reference format
            if s_type in ("NVD_CATALOG", "CISA_KEV_FEED") and not s_id.startswith("CVE-"):
                missing_evidence.append({
                    "item": f"Invalid Source Reference: {s_id}",
                    "reason": f"Source ID '{s_id}' does not conform to NVD/CISA CVE catalog schema.",
                })
                unverified_claims.append(f"Invalid reference {s_id} rejected from verified findings.")
                continue

            find_key = (s_type, s_id, claim_text)
            if find_key not in seen_findings:
                seen_findings.add(find_key)
                deduped_confirmed.append(f)
        confirmed_findings = deduped_confirmed

        # Deduplicate missing evidence by item name
        deduped_missing = []
        seen_missing = set()
        for m in missing_evidence:
            item_name = m.get("item")
            if item_name not in seen_missing:
                seen_missing.add(item_name)
                deduped_missing.append(m)
        missing_evidence = deduped_missing

        # Status determination
        if contradictions:
            status = VerificationStatus.CONTRADICTION_DETECTED.value
            confidence = 0.50
        elif missing_evidence and (not confirmed_findings or len(confirmed_findings) == 0):
            status = VerificationStatus.UNVERIFIED.value if not verified_facts or len(verified_facts) <= 1 else VerificationStatus.PARTIALLY_SUPPORTED.value
            confidence = 0.45
        elif missing_evidence:
            status = VerificationStatus.PARTIALLY_SUPPORTED.value
            confidence = 0.85
        else:
            status = VerificationStatus.CONFIRMED.value
            confidence = 0.98

        summary = (
            f"Verification status: {status} (confidence={int(confidence * 100)}%). "
            f"Confirmed findings: {len(confirmed_findings)}, Hypotheses: {len(hypotheses)}, "
            f"Missing evidence items: {len(missing_evidence)}, Contradictions: {len(contradictions)}."
        )

        res = VerificationResult(
            status=status,
            verified_facts=verified_facts,
            unverified_claims=unverified_claims,
            contradictions_detected=contradictions,
            confidence_score=confidence,
            confirmed_findings=confirmed_findings,
            hypotheses=hypotheses,
            missing_evidence=missing_evidence,
            summary=summary,
        )

        return {
            "verification": res.to_dict(),
            "confirmed_findings": confirmed_findings,
            "hypotheses": hypotheses,
            "missing_evidence": missing_evidence,
        }


# =============================================================================
# 8. Remediation Specialist Agent
# =============================================================================

class RemediationAgent:
    """
    Remediation Specialist Agent:
    Synthesizes actionable, verified remediation plans for identified vulnerabilities,
    explains why each action is recommended, distinguishes verified facts from proposed actions,
    cites authoritative vendor advisories, evaluates operational blast radius / rollback,
    and identifies missing version or asset information.
    """

    def __init__(self):
        self.role = AgentRole.REMEDIATION.value
        self.groq = get_groq_client()

    def run(self, state: InvestigationState) -> Dict[str, Any]:
        """Executes remediation analysis against verified findings and target CVEs/assets."""
        query = state.get("query", "")
        targets = state.get("targets", {})
        target_cves = targets.get("cve_ids") or []
        target_assets = targets.get("asset_ids") or []
        target_findings = targets.get("finding_ids") or []
        tenant_id = state.get("tenant_id")
        user_role = state.get("user_role", "SOC_ANALYST")

        # Security check
        if detect_prompt_injection(query):
            logger.warning("Adversarial prompt injection pattern detected in remediation query.")

        import services.remediation_engine as rem_engine_mod
        engine = rem_engine_mod.remediation_engine

        remediation_plans: List[Dict[str, Any]] = []
        missing_info: List[str] = []
        recommended_actions: List[str] = []
        advisories: List[Dict[str, Any]] = []
        prerequisites: List[str] = []
        verification_steps: List[str] = []
        rollback_considerations: List[str] = []

        # 1. Inspect target findings
        if target_findings:
            for fid in target_findings:
                plan = engine.get_plan(fid)
                if not plan:
                    try:
                        plan = engine.create_plan_from_finding(fid, creator_role=user_role)
                    except Exception as e:
                        logger.warning(f"Could not auto-generate plan for finding {fid}: {e}")
                if plan:
                    remediation_plans.append(plan)

        # 2. Check for target CVEs if no plans yet
        if not remediation_plans and target_cves:
            for cve in target_cves:
                matched_plans = engine.list_plans(cve_id=cve)
                if matched_plans:
                    remediation_plans.extend(matched_plans)
                else:
                    # Check if there is an unaddressed finding for this CVE
                    findings = tool_get_correlated_findings(cve_id=cve, limit=5)
                    for f in findings:
                        fid = f.get("findingId") or f.get("finding_id")
                        if fid:
                            try:
                                plan = engine.create_plan_from_finding(fid, creator_role=user_role)
                                remediation_plans.append(plan)
                            except Exception:
                                pass

        # 3. Check for target assets if still no plans
        if not remediation_plans and target_assets:
            for ast in target_assets:
                matched_plans = engine.list_plans(asset_id=ast)
                if matched_plans:
                    remediation_plans.extend(matched_plans)

        # 4. If query is broad, fetch top priority plans
        if not remediation_plans:
            remediation_plans = engine.list_plans()[:5]

        # Extract structured details from remediation plans
        for p in remediation_plans:
            steps = p.get("recommended_steps") or []
            if isinstance(steps, list):
                recommended_actions.extend(steps)
            advs = p.get("vendor_advisories") or []
            if isinstance(advs, list):
                advisories.extend(advs)
            v_steps = p.get("verification_steps") or []
            if isinstance(v_steps, list):
                verification_steps.extend(v_steps)
            r_backs = p.get("rollback_considerations") or []
            if isinstance(r_backs, list):
                rollback_considerations.extend(r_backs)

            prereqs_dict = p.get("prerequisites") or {}
            if isinstance(prereqs_dict, dict):
                prereqs_list = prereqs_dict.get("prerequisites") or []
                prerequisites.extend(prereqs_list)
                if not prereqs_dict.get("authoritative_fix_known", True):
                    missing_info.append(
                        f"Authoritative vendor patch unknown for {p.get('cve_id')}; specific package version confirmation required from asset owner."
                    )

        # De-duplicate lists
        recommended_actions = list(dict.fromkeys(recommended_actions))
        verification_steps = list(dict.fromkeys(verification_steps))
        rollback_considerations = list(dict.fromkeys(rollback_considerations))
        prerequisites = list(dict.fromkeys(prerequisites))

        operational_impact = "Standard service maintenance window required."
        if any(p.get("priority") == "IMMEDIATE" for p in remediation_plans):
            operational_impact = "High urgency: Emergency maintenance window required; restart or session termination anticipated."

        summary = (
            f"Remediation analysis active for {len(remediation_plans)} plan(s). "
            f"Recommended actions: {len(recommended_actions)}, Authoritative advisories: {len(advisories)}. "
            f"Missing information items: {len(missing_info)}."
        )

        res = RemediationResult(
            remediation_plans=remediation_plans,
            recommended_actions=recommended_actions,
            authoritative_advisories=advisories,
            prerequisites=prerequisites,
            verification_steps=verification_steps,
            rollback_considerations=rollback_considerations,
            operational_impact=operational_impact,
            missing_information=missing_info,
            summary=summary,
        )

        return {
            "remediation": res.to_dict(),
            "remediation_plans": remediation_plans,
            "recommended_actions": recommended_actions,
        }

