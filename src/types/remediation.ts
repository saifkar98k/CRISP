/**
 * CRISP Remediation Intelligence Engine - TypeScript Types
 */

export type RemediationStatus =
  | 'OPEN'
  | 'PLANNED'
  | 'AWAITING_APPROVAL'
  | 'IN_PROGRESS'
  | 'AWAITING_VERIFICATION'
  | 'RESOLVED'
  | 'REOPENED';

export type ApprovalStatus =
  | 'NOT_REQUIRED'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'REJECTED';

export type RemediationPriority =
  | 'IMMEDIATE'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW';

export interface VendorAdvisory {
  title: string;
  url?: string;
  notes?: string;
}

export interface StatusHistoryItem {
  timestamp: string;
  previous_status: string | null;
  new_status: RemediationStatus;
  updated_by: string;
  user_role: string;
  notes: string;
}

export interface VerificationEvidence {
  scanner_or_tool?: string;
  scan_id_or_version?: string;
  evidence_summary: string;
  is_clean?: boolean;
  timestamp?: string;
}

export interface RemediationPrerequisites {
  prerequisites: string[];
  operational_impact: string;
  authoritative_fix_known: boolean;
  action_type: string;
}

export interface RemediationPlan {
  remediation_id: string;
  finding_id: string;
  asset_id: string;
  asset_name: string;
  cve_id: string | null;
  current_risk_score: number;
  current_severity: string;
  priority: RemediationPriority;
  summary: string;
  evidence: string[];
  recommended_steps: string[];
  vendor_advisories: VendorAdvisory[];
  verification_steps: string[];
  rollback_considerations: string[];
  prerequisites: RemediationPrerequisites;
  approval_status: ApprovalStatus;
  remediation_status: RemediationStatus;
  assigned_to: string;
  verification_evidence: VerificationEvidence | null;
  post_remediation_risk_score: number | null;
  risk_reduction: number | null;
  status_history: StatusHistoryItem[];
  created_at: string;
  updated_at: string;
}
