/**
 * CRISP - Cyber Risk Intelligence & Scoring Platform
 * Normalized Internal Schemas
 *
 * All external data from NVD, CISA KEV, or external CSVs are converted
 * into these strict internal schemas before reaching the database,
 * risk engine, or dashboard.
 */

export type DataSourceOrigin =
  | 'NVD_API'               // Real external public vulnerability database
  | 'CISA_KEV'              // Real external CISA Known Exploited Vulnerabilities catalog
  | 'HISTORICAL_DATASET'    // Real external public cybersecurity incident dataset
  | 'SYNTHETIC_DEMO'        // Simulated mock event strictly for controlled demonstration
  | 'CRISP_DERIVED';        // Calculated operational risk score or compliance metric

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface Vulnerability {
  id: string; // CVE ID (e.g. CVE-2021-44228)
  title: string;
  description: string;
  cvssScore: number; // 0.0 - 10.0
  cvssVector?: string;
  severity: VulnerabilitySeverity;
  affectedProducts: string[];
  cwe: string[];
  publishedDate: string; // ISO 8601
  modifiedDate: string;  // ISO 8601
  references: string[];
  
  // CISA KEV Enrichment fields
  isKnownExploited: boolean;
  kevDateAdded?: string;
  kevVendorProject?: string;
  kevProduct?: string;
  kevVulnerabilityName?: string;
  kevRequiredAction?: string;
  kevDueDate?: string;
  
  // Provenance & Audit
  dataSource: 'NVD_API' | 'CISA_KEV' | 'SYNTHETIC_DEMO';
  isRealData: boolean;
  lastRetrievedAt: string;
}

export type EventSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface SecurityEvent {
  id: string;
  timestamp: string; // ISO 8601
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  assetId?: string;
  assetName?: string;
  assetCriticality?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  attackCategory: string;
  originalAttackLabel?: string;
  crispAttackCategory?: string;
  severity: EventSeverity;
  description: string;
  relatedCveId?: string;
  detectionRule?: string;
  nistFunction?: string;
  status: 'ACTIVE' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'HISTORICAL_RECORD';
  crispRiskScore?: number;
  
  // Provenance & Audit
  dataSource: 'HISTORICAL_DATASET' | 'SYNTHETIC_DEMO' | 'CIC-IDS2017' | string;
  datasetSource?: 'CIC-IDS2017' | 'MOCK' | 'HISTORICAL_DATASET' | string;
  isRealData: boolean;
}

export interface SecurityFinding {
  findingId: string;
  timestamp: string;
  assetId?: string;
  assetName?: string;
  eventId?: string;
  cveId?: string;
  attackCategory: string;
  severity: EventSeverity;
  cvssScore?: number;
  knownExploited: boolean;
  assetCriticality?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  riskScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  nistFunction: 'GOVERN' | 'IDENTIFY' | 'PROTECT' | 'DETECT' | 'RESPOND' | 'RECOVER' | string;
  evidence: string[];
  source: string;
}

export interface Asset {
  id: string;
  name: string;
  ipAddress: string;
  type: 'Web Application' | 'Database Server' | 'API Gateway' | 'Domain Controller' | 'Endpoint' | 'Cloud Storage';
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  exposure: 'EXTERNAL' | 'DMZ' | 'INTERNAL' | 'ISOLATED';
  owner: string;
  department: string;
  vulnerabilityCount: number;
  calculatedRiskScore: number;
}

export interface RiskFactorContribution {
  factor: string;
  value: string | number;
  weight: number;
  scoreContribution: number;
  description: string;
}

export interface RiskScoreBreakdown {
  targetId: string;
  targetType: 'ASSET' | 'VULNERABILITY' | 'SYSTEM_OVERALL';
  overallScore: number; // 0.0 - 10.0
  severityTier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  calculatedAt: string;
  factors: RiskFactorContribution[];
  formulaExplanation: string;
  isDerivedScore: true;
  disclaimer: string;
}

export interface NistControlEvaluation {
  id: string; // e.g. ID.AM-1, PR.DS-1, DE.CM-1
  category: string;
  subcategory: string;
  function: 'GOVERN' | 'IDENTIFY' | 'PROTECT' | 'DETECT' | 'RESPOND' | 'RECOVER';
  score: number; // 0 - 100%
  status: 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT';
  findings: string;
  requiredRemediation?: string;
  evidence: string;
}

export interface NistComplianceSummary {
  overallCompliancePct: number;
  evaluatedAt: string;
  functionScores: {
    govern: number;
    identify: number;
    protect: number;
    detect: number;
    respond: number;
    recover: number;
  };
  totalControls: number;
  compliantCount: number;
  partialCount: number;
  nonCompliantCount: number;
  kevOverdueCount: number;
}

export interface DataSourceStatus {
  sourceName: string;
  type: 'EXTERNAL_API' | 'STATIC_DATASET' | 'SYNTHETIC_GENERATOR';
  originCategory: 'REAL_EXTERNAL' | 'REAL_HISTORICAL' | 'SYNTHETIC_DEMO';
  recordCount: number;
  lastUpdated: string;
  status: 'CONNECTED' | 'ACTIVE' | 'DEGRADED' | 'RATE_LIMITED' | 'IDLE';
  latencyMs: number;
  endpointOrPath: string;
  cached: boolean;
  notes: string;
}

export interface PipelineExecutionLog {
  id: string;
  stage: 'EXTRACT' | 'NORMALIZE' | 'VALIDATE' | 'SQLITE_LOAD' | 'RISK_ENGINE' | 'COMPLIANCE_ENGINE';
  timestamp: string;
  status: 'SUCCESS' | 'WARNING' | 'ERROR';
  recordsProcessed: number;
  message: string;
  durationMs: number;
}
