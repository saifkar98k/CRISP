"""
CRISP Agent Swarm 2.0 - Typed Schemas & State Definitions
Defines schemas for agent inputs, outputs, workflow classifications,
factual claim traceability, and shared investigation state.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    THREAT_INTEL = "threat_intel"
    VULN_INTEL = "vuln_intel"
    ASSET_RISK = "asset_risk"
    COMPLIANCE = "compliance"
    EVIDENCE = "evidence"
    VERIFICATION = "verification"
    REMEDIATION = "remediation"


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"
    SOC_ANALYST = "SOC_ANALYST"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    AUDITOR = "AUDITOR"
    CISO = "CISO"
    READONLY_ANALYST = "READONLY_ANALYST"


AUTHORIZED_ROLES = {
    UserRole.ADMIN.value,
    UserRole.SECURITY_ANALYST.value,
    UserRole.SOC_ANALYST.value,
    UserRole.SECURITY_ADMIN.value,
    UserRole.AUDITOR.value,
    UserRole.CISO.value,
    "ADMIN",
    "SECURITY_ANALYST",
    "SOC_ANALYST",
    "SECURITY_ADMIN",
    "AUDITOR",
    "CISO",
}


class WorkflowType(str, Enum):
    ASSET_INVESTIGATION = "ASSET_INVESTIGATION"
    CVE_INVESTIGATION = "CVE_INVESTIGATION"
    EVENT_INVESTIGATION = "EVENT_INVESTIGATION"
    FINDING_INVESTIGATION = "FINDING_INVESTIGATION"
    GENERAL_QUESTION = "GENERAL_QUESTION"


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNVERIFIED = "UNVERIFIED"
    CONTRADICTION_DETECTED = "CONTRADICTION_DETECTED"


class FactualClaim:
    """Represents a factual claim traceable to an authentic CRISP database record or document."""

    def __init__(
        self,
        claim: str,
        source_type: str,  # 'DATABASE_RECORD', 'CISA_KEV_FEED', 'NVD_CATALOG', 'RAG_DOCUMENT', 'CALCULATED_MODEL'
        source_id: str,    # CVE-XXXX-XXXX, AST-XXXX, SIM-XXXX, FND-XXXX, GV.OC-01
        source_table: str = "",
        source_url: Optional[str] = None,
        is_verified: bool = True,
    ):
        self.claim = claim
        self.source_type = source_type
        self.source_id = source_id
        self.source_table = source_table
        self.source_url = source_url
        self.is_verified = is_verified

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "source_table": self.source_table,
            "source_url": self.source_url,
            "is_verified": self.is_verified,
        }


class InvestigationTarget:
    """Parsed investigation targets extracted from query."""

    def __init__(
        self,
        cve_ids: Optional[List[str]] = None,
        asset_ids: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        event_ids: Optional[List[str]] = None,
        finding_ids: Optional[List[str]] = None,
        attack_categories: Optional[List[str]] = None,
        nist_functions: Optional[List[str]] = None,
        primary_target_type: str = "GENERAL",
        primary_target_id: Optional[str] = None,
        raw_query: str = "",
        prompt_injection_detected: bool = False,
    ):
        self.cve_ids = cve_ids or []
        self.asset_ids = asset_ids or []
        self.ips = ips or []
        self.event_ids = event_ids or []
        self.finding_ids = finding_ids or []
        self.attack_categories = attack_categories or []
        self.nist_functions = nist_functions or []
        self.primary_target_type = primary_target_type
        self.primary_target_id = primary_target_id
        self.raw_query = raw_query
        self.prompt_injection_detected = prompt_injection_detected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_ids": self.cve_ids,
            "asset_ids": self.asset_ids,
            "ips": self.ips,
            "event_ids": self.event_ids,
            "finding_ids": self.finding_ids,
            "attack_categories": self.attack_categories,
            "nist_functions": self.nist_functions,
            "primary_target_type": self.primary_target_type,
            "primary_target_id": self.primary_target_id,
            "raw_query": self.raw_query,
            "prompt_injection_detected": self.prompt_injection_detected,
        }


class InvestigationPlan:
    """Investigation plan produced by Orchestrator Agent."""

    def __init__(
        self,
        workflow_type: str = WorkflowType.GENERAL_QUESTION.value,
        target_agents: Optional[List[str]] = None,
        priorities: Optional[Dict[str, int]] = None,
        rationale: str = "",
        targets: Optional[Dict[str, Any]] = None,
        requires_evidence_refinement: bool = False,
    ):
        self.workflow_type = workflow_type
        self.target_agents = target_agents or [
            AgentRole.THREAT_INTEL.value,
            AgentRole.VULN_INTEL.value,
            AgentRole.ASSET_RISK.value,
            AgentRole.COMPLIANCE.value,
            AgentRole.EVIDENCE.value,
        ]
        self.priorities = priorities or {}
        self.rationale = rationale
        self.targets = targets or {}
        self.requires_evidence_refinement = requires_evidence_refinement

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_type": self.workflow_type,
            "target_agents": self.target_agents,
            "priorities": self.priorities,
            "rationale": self.rationale,
            "targets": self.targets,
            "requires_evidence_refinement": self.requires_evidence_refinement,
        }


class ThreatIntelResult:
    """Output from Threat Intelligence Agent."""

    def __init__(
        self,
        observed_events_count: int = 0,
        attack_categories: Optional[List[str]] = None,
        top_source_ips: Optional[List[str]] = None,
        correlated_findings: Optional[List[Dict[str, Any]]] = None,
        severity_breakdown: Optional[Dict[str, int]] = None,
        summary: str = "",
        raw_events: Optional[List[Dict[str, Any]]] = None,
        event_ids: Optional[List[str]] = None,
        attributed_assets: Optional[List[str]] = None,
    ):
        self.observed_events_count = observed_events_count
        self.attack_categories = attack_categories or []
        self.top_source_ips = top_source_ips or []
        self.correlated_findings = correlated_findings or []
        self.severity_breakdown = severity_breakdown or {}
        self.summary = summary
        self.raw_events = raw_events or []
        self.event_ids = event_ids or []
        self.attributed_assets = attributed_assets or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observed_events_count": self.observed_events_count,
            "attack_categories": self.attack_categories,
            "top_source_ips": self.top_source_ips,
            "correlated_findings": self.correlated_findings,
            "severity_breakdown": self.severity_breakdown,
            "summary": self.summary,
            "event_ids": self.event_ids[:10],
            "attributed_assets": self.attributed_assets,
            "sample_events_count": len(self.raw_events),
        }


class VulnerabilityIntelResult:
    """Output from Vulnerability Intelligence Agent."""

    def __init__(
        self,
        cves_analyzed: Optional[List[str]] = None,
        known_exploited_matches: Optional[List[Dict[str, Any]]] = None,
        max_cvss_score: float = 0.0,
        highest_severity: str = "UNKNOWN",
        affected_products: Optional[List[str]] = None,
        summary: str = "",
        details: Optional[List[Dict[str, Any]]] = None,
        affected_asset_ids: Optional[List[str]] = None,
        source_references: Optional[List[str]] = None,
    ):
        self.cves_analyzed = cves_analyzed or []
        self.known_exploited_matches = known_exploited_matches or []
        self.max_cvss_score = max_cvss_score
        self.highest_severity = highest_severity
        self.affected_products = affected_products or []
        self.summary = summary
        self.details = details or []
        self.affected_asset_ids = affected_asset_ids or []
        self.source_references = source_references or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cves_analyzed": self.cves_analyzed,
            "known_exploited_matches": self.known_exploited_matches,
            "max_cvss_score": self.max_cvss_score,
            "highest_severity": self.highest_severity,
            "affected_products": self.affected_products,
            "affected_asset_ids": self.affected_asset_ids,
            "source_references": self.source_references[:5],
            "summary": self.summary,
            "vulnerabilities_count": len(self.details),
        }


class AssetRiskResult:
    """Output from Asset Risk Agent."""

    def __init__(
        self,
        assets_analyzed: Optional[List[str]] = None,
        highest_criticality: str = "UNKNOWN",
        calculated_risk_score: float = 0.0,
        risk_level: str = "LOW",
        factor_breakdown: Optional[Dict[str, Any]] = None,
        exposure_status: str = "UNKNOWN",
        summary: str = "",
        asset_details: Optional[List[Dict[str, Any]]] = None,
        mapped_cves: Optional[List[str]] = None,
        historical_risk_assessments: Optional[List[Dict[str, Any]]] = None,
    ):
        self.assets_analyzed = assets_analyzed or []
        self.highest_criticality = highest_criticality
        self.calculated_risk_score = calculated_risk_score
        self.risk_level = risk_level
        self.factor_breakdown = factor_breakdown or {}
        self.exposure_status = exposure_status
        self.summary = summary
        self.asset_details = asset_details or []
        self.mapped_cves = mapped_cves or []
        self.historical_risk_assessments = historical_risk_assessments or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assets_analyzed": self.assets_analyzed,
            "highest_criticality": self.highest_criticality,
            "calculated_risk_score": self.calculated_risk_score,
            "risk_level": self.risk_level,
            "factor_breakdown": self.factor_breakdown,
            "exposure_status": self.exposure_status,
            "summary": self.summary,
            "mapped_cves": self.mapped_cves,
            "asset_count": len(self.asset_details),
            "historical_assessments_count": len(self.historical_risk_assessments),
        }


class ComplianceResult:
    """Output from Compliance Agent."""

    def __init__(
        self,
        affected_functions: Optional[List[str]] = None,
        relevant_controls: Optional[List[Dict[str, Any]]] = None,
        compliance_gaps: Optional[List[str]] = None,
        remediation_priorities: Optional[List[str]] = None,
        overall_compliance_score: float = 100.0,
        summary: str = "",
        control_evidence: Optional[Dict[str, str]] = None,
    ):
        self.affected_functions = affected_functions or []
        self.relevant_controls = relevant_controls or []
        self.compliance_gaps = compliance_gaps or []
        self.remediation_priorities = remediation_priorities or []
        self.overall_compliance_score = overall_compliance_score
        self.summary = summary
        self.control_evidence = control_evidence or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "affected_functions": self.affected_functions,
            "relevant_controls": self.relevant_controls,
            "compliance_gaps": self.compliance_gaps,
            "remediation_priorities": self.remediation_priorities,
            "overall_compliance_score": self.overall_compliance_score,
            "summary": self.summary,
            "control_evidence": self.control_evidence,
        }


class EvidenceResult:
    """Output from Evidence Agent."""

    def __init__(
        self,
        retrieved_documents: Optional[List[Dict[str, Any]]] = None,
        collections_searched: Optional[List[str]] = None,
        citations: Optional[List[str]] = None,
        avg_relevance_score: float = 0.0,
        summary: str = "",
    ):
        self.retrieved_documents = retrieved_documents or []
        self.collections_searched = collections_searched or []
        self.citations = citations or []
        self.avg_relevance_score = avg_relevance_score
        self.summary = summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "retrieved_documents_count": len(self.retrieved_documents),
            "collections_searched": self.collections_searched,
            "citations": self.citations,
            "avg_relevance_score": self.avg_relevance_score,
            "summary": self.summary,
            "documents": self.retrieved_documents[:5],
        }


class VerificationResult:
    """Output from Verification Agent with strict factual separation."""

    def __init__(
        self,
        status: str = VerificationStatus.CONFIRMED.value,
        verified_facts: Optional[List[str]] = None,
        unverified_claims: Optional[List[str]] = None,
        contradictions_detected: Optional[List[str]] = None,
        confidence_score: float = 1.0,
        confirmed_findings: Optional[List[Dict[str, Any]]] = None,
        hypotheses: Optional[List[Dict[str, Any]]] = None,
        missing_evidence: Optional[List[Dict[str, Any]]] = None,
        summary: str = "",
    ):
        self.status = status
        self.verified_facts = verified_facts or []
        self.unverified_claims = unverified_claims or []
        self.contradictions_detected = contradictions_detected or []
        self.confidence_score = confidence_score
        self.confirmed_findings = confirmed_findings or []
        self.hypotheses = hypotheses or []
        self.missing_evidence = missing_evidence or []
        self.summary = summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "confidence_score": self.confidence_score,
            "verified_facts": self.verified_facts,
            "unverified_claims": self.unverified_claims,
            "contradictions_detected": self.contradictions_detected,
            "confirmed_findings": self.confirmed_findings,
            "hypotheses": self.hypotheses,
            "missing_evidence": self.missing_evidence,
            "summary": self.summary,
        }


class RemediationResult:
    """Output from Remediation Specialist Agent."""

    def __init__(
        self,
        remediation_plans: Optional[List[Dict[str, Any]]] = None,
        recommended_actions: Optional[List[str]] = None,
        authoritative_advisories: Optional[List[Dict[str, Any]]] = None,
        prerequisites: Optional[List[str]] = None,
        verification_steps: Optional[List[str]] = None,
        rollback_considerations: Optional[List[str]] = None,
        operational_impact: str = "",
        missing_information: Optional[List[str]] = None,
        summary: str = "",
    ):
        self.remediation_plans = remediation_plans or []
        self.recommended_actions = recommended_actions or []
        self.authoritative_advisories = authoritative_advisories or []
        self.prerequisites = prerequisites or []
        self.verification_steps = verification_steps or []
        self.rollback_considerations = rollback_considerations or []
        self.operational_impact = operational_impact
        self.missing_information = missing_information or []
        self.summary = summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "remediation_plans_count": len(self.remediation_plans),
            "remediation_plans": self.remediation_plans,
            "recommended_actions": self.recommended_actions,
            "authoritative_advisories": self.authoritative_advisories,
            "prerequisites": self.prerequisites,
            "verification_steps": self.verification_steps,
            "rollback_considerations": self.rollback_considerations,
            "operational_impact": self.operational_impact,
            "missing_information": self.missing_information,
            "summary": self.summary,
        }


class InvestigationState(dict):
    """
    Shared investigation state passed between all nodes in the LangGraph swarm.
    Subclasses dict for direct compatibility with LangGraph and JSON serialization.
    """

    def __init__(
        self,
        query: str,
        target_cve: Optional[str] = None,
        target_asset: Optional[str] = None,
        user_role: str = "SOC_ANALYST",
        **kwargs: Any,
    ):
        super().__init__()
        self["investigation_id"] = kwargs.get(
            "investigation_id",
            f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')[:17]}",
        )
        self["created_at"] = kwargs.get(
            "created_at", datetime.now(timezone.utc).isoformat()
        )
        self["query"] = query
        self["target_cve"] = target_cve
        self["target_asset"] = target_asset
        self["user_role"] = user_role
        self["tenant_id"] = kwargs.get("tenant_id", None)

        # Workflow & Target parser output
        self["workflow_type"] = kwargs.get(
            "workflow_type", WorkflowType.GENERAL_QUESTION.value
        )
        self["targets"] = kwargs.get("targets", {})

        # Plan
        self["plan"] = kwargs.get("plan", None)

        # Specialized Agent Outputs
        self["threat_intel"] = kwargs.get("threat_intel", None)
        self["vuln_intel"] = kwargs.get("vuln_intel", None)
        self["asset_risk"] = kwargs.get("asset_risk", None)
        self["compliance"] = kwargs.get("compliance", None)
        self["evidence"] = kwargs.get("evidence", None)
        self["verification"] = kwargs.get("verification", None)
        self["remediation"] = kwargs.get("remediation", None)

        # Explicit Fact vs Hypothesis vs Missing Evidence
        self["confirmed_findings"] = kwargs.get("confirmed_findings", [])
        self["hypotheses"] = kwargs.get("hypotheses", [])
        self["missing_evidence"] = kwargs.get("missing_evidence", [])
        self["citations"] = kwargs.get("citations", [])

        # Final Synthesis Output
        self["final_report"] = kwargs.get("final_report", None)
        self["executive_summary"] = kwargs.get("executive_summary", "")
        self["recommended_actions"] = kwargs.get("recommended_actions", [])
        self["overall_risk_rating"] = kwargs.get("overall_risk_rating", "MEDIUM")
        self["overall_risk_score"] = kwargs.get("overall_risk_score", 0.0)

        # Swarm execution telemetry & metrics
        self["execution_trace"] = kwargs.get("execution_trace", [])
        self["errors"] = kwargs.get("errors", [])
        self["active_agents"] = kwargs.get("active_agents", [])
        self["duration_ms"] = kwargs.get("duration_ms", 0)
        self["agent_success_rate"] = kwargs.get("agent_success_rate", 1.0)
        self["investigation_completeness"] = kwargs.get("investigation_completeness", 1.0)
        self["token_usage"] = kwargs.get("token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})

        for k, v in kwargs.items():
            if k not in self:
                self[k] = v
