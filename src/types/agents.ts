/**
 * CRISP Agent Swarm 2.0 - TypeScript Interfaces & Types
 */

export type AgentRoleName =
  | 'orchestrator'
  | 'threat_intel'
  | 'vuln_intel'
  | 'asset_risk'
  | 'compliance'
  | 'evidence'
  | 'verification';

export type AgentExecutionStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'skipped';

export type InvestigationWorkflowType =
  | 'GENERAL_QUESTION'
  | 'ASSET_INVESTIGATION'
  | 'CVE_INVESTIGATION'
  | 'EVENT_INVESTIGATION'
  | 'CRITICAL_FINDING_INVESTIGATION';

export interface AgentStatusInfo {
  role: AgentRoleName;
  name: string;
  status: AgentExecutionStatus;
  message?: string;
  error?: string;
  startedAt?: number;
  completedAt?: number;
  data?: any;
}

export interface FactualClaim {
  claim_text: string;
  source_type: string;
  source_id: string;
  is_verified: boolean;
  confidence: number;
}

export interface VerificationData {
  verification_status: 'VERIFIED' | 'PARTIALLY_VERIFIED' | 'CONTRADICTED' | 'INSUFFICIENT_EVIDENCE';
  is_consistent: boolean;
  verified_claims: string[];
  hypotheses: string[];
  contradictions_detected: string[];
  unsupported_claims: string[];
  missing_evidence: string[];
  audit_trail: Array<{
    rule: string;
    status: string;
    detail: string;
  }>;
}

export interface ThreatIntelData {
  analyzed_events_count: number;
  primary_attack_categories: string[];
  detected_anomalies: string[];
  mitre_tactics: string[];
  threat_severity_distribution: Record<string, number>;
  active_attack_vectors: string[];
  correlated_findings_count: number;
}

export interface VulnIntelData {
  analyzed_cves: string[];
  cisa_kev_matches: string[];
  max_cvss_score: number;
  affected_vendors: string[];
  common_cwe_weaknesses: string[];
  actionable_remediations: string[];
}

export interface AssetRiskData {
  evaluated_assets: string[];
  max_criticality: string;
  average_risk_score: number;
  network_exposures: string[];
  risk_factors: string[];
  top_risk_asset?: string;
}

export interface ComplianceData {
  evaluated_nist_functions: string[];
  nist_subcategories: string[];
  compliance_readiness_score: number;
  audit_evidence_findings: string[];
  non_compliant_gaps: string[];
}

export interface EvidenceDocument {
  id: string;
  collection: string;
  distance: number;
  document: string;
  metadata?: Record<string, any>;
}

export interface EvidenceData {
  retrieved_documents_count: number;
  collections_queried: string[];
  citations: string[];
  retrieved_documents: EvidenceDocument[];
}

export interface OrchestratorPlan {
  workflow_type: InvestigationWorkflowType;
  primary_objective: string;
  target_agents: AgentRoleName[];
  requires_evidence_refinement: boolean;
  priority_level: string;
}

export interface InvestigationReport {
  investigation_id: string;
  query: string;
  workflow_type: InvestigationWorkflowType;
  target_cve?: string | null;
  target_asset?: string | null;
  overall_risk_score: number;
  overall_risk_rating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  executive_summary: string;
  confirmed_findings: string[];
  hypotheses: string[];
  missing_evidence: string[];
  contradictions_detected: string[];
  nist_mappings: Record<string, string[]>;
  recommendations: string[];
  agent_results?: {
    threat_intel?: ThreatIntelData;
    vuln_intel?: VulnIntelData;
    asset_risk?: AssetRiskData;
    compliance?: ComplianceData;
    evidence?: EvidenceData;
  };
  threat_intel?: ThreatIntelData;
  vuln_intel?: VulnIntelData;
  asset_risk?: AssetRiskData;
  compliance?: ComplianceData;
  evidence?: EvidenceData;
  verification?: VerificationData;
  duration_ms?: number;
  errors?: Array<{ agent: string; error: string }>;
  agent_failures?: string[];
  created_at?: string;
}

export interface InvestigationHistoryItem {
  investigation_id: string;
  timestamp: string;
  query: string;
  workflow_type: InvestigationWorkflowType;
  target_cve?: string;
  target_asset?: string;
  overall_risk_score: number;
  overall_risk_rating: string;
  verification_status: string;
  executive_summary?: string;
}

export interface SwarmStatus {
  status: string;
  version: string;
  architecture: string;
  has_native_langgraph: boolean;
  groq_integration: {
    is_configured: boolean;
    model: string;
    timeout_seconds: number;
  };
  agents: Array<{
    role: string;
    name: string;
    description: string;
    read_only: boolean;
  }>;
  safety_controls: {
    arbitrary_shell_disabled: boolean;
    arbitrary_sql_disabled: boolean;
    read_only_enforced: boolean;
    concurrency_enabled: boolean;
    bounded_retries: boolean;
  };
}

export interface ClassicAssistantResponse {
  answer: string;
  sources: EvidenceDocument[];
  model: string;
  is_configured: boolean;
}
