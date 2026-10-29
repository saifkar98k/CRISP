/**
 * CRISP Cyber Risk Intelligence & Scoring Platform
 * CRISP Agent Swarm 2.0 - Supervised Multi-Agent SOC Investigation Interface
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Bot,
  BrainCircuit,
  Play,
  Square,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Search,
  Sparkles,
  Terminal,
  FileText,
  ExternalLink,
  RefreshCw,
  Layers,
  HelpCircle,
  Database,
  Award,
  Activity,
  History,
  AlertCircle,
  ChevronRight,
  ChevronDown,
  RotateCcw,
  Check,
  Minimize2,
  Maximize2,
  Lock,
  Cpu,
  MinusCircle,
  Sliders,
} from 'lucide-react';
import {
  AgentRoleName,
  AgentExecutionStatus,
  InvestigationWorkflowType,
  AgentStatusInfo,
  InvestigationReport,
  InvestigationHistoryItem,
  SwarmStatus,
  ClassicAssistantResponse,
} from '../types/agents';

const AGENT_METADATA: Record<
  AgentRoleName,
  { name: string; icon: React.ElementType; color: string; description: string }
> = {
  orchestrator: {
    name: 'Orchestrator Agent',
    icon: BrainCircuit,
    color: 'text-cyan-400 border-cyan-800 bg-cyan-950/60',
    description: 'Plans investigation scope, coordinates domain agents, and synthesizes final executive reports.',
  },
  threat_intel: {
    name: 'Threat Intelligence Agent',
    icon: Activity,
    color: 'text-amber-400 border-amber-800 bg-amber-950/60',
    description: 'Analyzes live and historical security event telemetry, anomalies, and MITRE ATT&CK tactics.',
  },
  vuln_intel: {
    name: 'Vulnerability Intelligence Agent',
    icon: Shield,
    color: 'text-rose-400 border-rose-800 bg-rose-950/60',
    description: 'Queries NVD CVE catalog, CVSS vectors, CWE weaknesses, and CISA Known Exploited Vulnerabilities.',
  },
  asset_risk: {
    name: 'Asset Risk Agent',
    icon: Cpu,
    color: 'text-purple-400 border-purple-800 bg-purple-950/60',
    description: 'Evaluates asset criticality, network exposure, and multi-factor risk scores from CRISP engine.',
  },
  compliance: {
    name: 'Compliance Agent',
    icon: Award,
    color: 'text-emerald-400 border-emerald-800 bg-emerald-950/60',
    description: 'Maps findings to NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover).',
  },
  evidence: {
    name: 'Evidence Agent',
    icon: Database,
    color: 'text-blue-400 border-blue-800 bg-blue-950/60',
    description: 'Performs semantic retrieval across ChromaDB vector collections with similarity grounding.',
  },
  verification: {
    name: 'Verification Agent',
    icon: CheckCircle2,
    color: 'text-teal-400 border-teal-800 bg-teal-950/60',
    description: 'Cross-checks evidence for contradictions, flags unsupported claims, and verifies source citations.',
  },
};

const PRESET_QUERIES: Array<{
  label: string;
  workflow: InvestigationWorkflowType;
  query: string;
  targetCve?: string;
  targetAsset?: string;
}> = [
  {
    label: 'CVE-2021-44228 Log4Shell Triage',
    workflow: 'CVE_INVESTIGATION',
    query: 'Investigate CVE-2021-44228 Log4Shell CVSS severity, CISA KEV exploitation status, and affected enterprise assets.',
    targetCve: 'CVE-2021-44228',
  },
  {
    label: 'Asset Audit: prod-edge-web01',
    workflow: 'ASSET_INVESTIGATION',
    query: 'Audit asset prod-edge-web01.internal (AST-PROD-WEB-01) for vulnerabilities, risk score, and compliance posture.',
    targetAsset: 'AST-PROD-WEB-01',
  },
  {
    label: 'Security Event Telemetry Audit',
    workflow: 'EVENT_INVESTIGATION',
    query: 'Investigate recent high-severity network intrusions, brute force, and port scanning events across monitored subnets.',
  },
  {
    label: 'Critical Finding Multidisciplinary Triage',
    workflow: 'CRITICAL_FINDING_INVESTIGATION',
    query: 'Perform full multidisciplinary investigation on CRITICAL correlated finding: active exploitation of public perimeter asset.',
  },
  {
    label: 'General Risk Assessment',
    workflow: 'GENERAL_QUESTION',
    query: 'What are the most urgent cyber risk vulnerabilities and NIST CSF compliance gaps requiring executive attention?',
  },
];

const ExecutiveSummaryCard: React.FC<{ summary: string }> = ({ summary }) => {
  if (!summary) return null;

  // Split lines and normalize
  const rawLines = summary.split('\n').map((l) => l.trim()).filter(Boolean);

  const formatInlineText = (str: string) => {
    const parts: React.ReactNode[] = [];
    const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
    let lastIndex = 0;
    let match;
    let keyIdx = 0;

    while ((match = regex.exec(str)) !== null) {
      if (match.index > lastIndex) {
        parts.push(str.substring(lastIndex, match.index));
      }
      const token = match[0];
      if (token.startsWith('**') && token.endsWith('**')) {
        const content = token.slice(2, -2);
        if (content.includes('ACTIVELY WEAPONIZED')) {
          parts.push(
            <span
              key={keyIdx++}
              className="inline-flex items-center gap-1 mx-1 px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold font-mono text-[11px] animate-pulse"
            >
              ⚠️ {content}
            </span>
          );
        } else if (content.includes('CONFIRMED')) {
          parts.push(
            <span
              key={keyIdx++}
              className="inline-flex items-center gap-1 mx-1 px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold font-mono text-[11px]"
            >
              ✅ {content}
            </span>
          );
        } else if (content.includes('Investigation Target:')) {
          parts.push(
            <span key={keyIdx++} className="text-cyan-400 font-bold uppercase tracking-wider text-[11px] mr-1">
              {content}
            </span>
          );
        } else {
          parts.push(
            <strong key={keyIdx++} className="text-white font-semibold">
              {content}
            </strong>
          );
        }
      } else if (token.startsWith('`') && token.endsWith('`')) {
        parts.push(
          <code
            key={keyIdx++}
            className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700/80 font-mono text-cyan-300 text-[11px] mx-1"
          >
            {token.slice(1, -1)}
          </code>
        );
      }
      lastIndex = regex.lastIndex;
    }
    if (lastIndex < str.length) {
      parts.push(str.substring(lastIndex));
    }
    return parts;
  };

  // Find target line
  const targetLine = rawLines.find((l) => l.includes('Investigation Target:'));
  const contentLines = rawLines.filter((l) => l !== targetLine);

  return (
    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3 shadow-xl">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
        <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span>Executive Intelligence Briefing</span>
        </div>
        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
          Synthesized Briefing
        </span>
      </div>

      {/* Target Scope Banner */}
      {targetLine && (
        <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-800/40 text-xs text-slate-200 flex items-start gap-2.5">
          <Sparkles className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed flex-1">
            {formatInlineText(targetLine)}
          </div>
        </div>
      )}

      {/* Structured Category Cards */}
      <div className="space-y-2">
        {contentLines.map((line, idx) => {
          const isSubDetail =
            line.startsWith('└') ||
            line.startsWith('L ') ||
            line.includes('Attribution:') ||
            line.includes('Affected enterprise asset');

          if (isSubDetail) {
            return (
              <div
                key={idx}
                className="ml-6 sm:ml-8 -mt-1 p-2 rounded-md bg-slate-900/90 border border-slate-800/70 text-[11px] text-slate-300 flex items-start gap-2 font-mono"
              >
                <span className="text-cyan-400 font-bold shrink-0">└</span>
                <span className="leading-relaxed">{formatInlineText(line.replace(/^[•\s*└L\s*]+/, ''))}</span>
              </div>
            );
          }

          let cardStyle = 'border-slate-800 bg-slate-900/60 text-slate-200';
          let icon = <FileText className="w-4 h-4 text-slate-400" />;

          if (line.includes('Vulnerability Intelligence')) {
            cardStyle = 'border-rose-905/40 bg-rose-950/20 text-slate-200 border-rose-800/40';
            icon = <Shield className="w-4 h-4 text-rose-400 shrink-0" />;
          } else if (line.includes('Threat Intelligence')) {
            cardStyle = 'border-amber-900/40 bg-amber-950/20 text-slate-200 border-amber-800/40';
            icon = <Activity className="w-4 h-4 text-amber-400 shrink-0" />;
          } else if (line.includes('Asset Risk')) {
            cardStyle = 'border-purple-900/40 bg-purple-950/20 text-slate-200 border-purple-800/40';
            icon = <Cpu className="w-4 h-4 text-purple-400 shrink-0" />;
          } else if (line.includes('NIST CSF 2.0 Compliance')) {
            cardStyle = 'border-emerald-900/40 bg-emerald-950/20 text-slate-200 border-emerald-800/40';
            icon = <Award className="w-4 h-4 text-emerald-400 shrink-0" />;
          } else if (line.includes('Evidence Verification')) {
            cardStyle = 'border-teal-900/40 bg-teal-950/20 text-slate-200 border-teal-800/40';
            icon = <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0" />;
          }

          const cleanText = line.replace(/^[•\s*]+/, '');

          return (
            <div
              key={idx}
              className={`p-3 rounded-lg border flex items-start gap-3 text-xs leading-relaxed transition-all ${cardStyle}`}
            >
              <div className="mt-0.5 shrink-0">{icon}</div>
              <div className="flex-1 leading-relaxed">
                {formatInlineText(cleanText)}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export const AgentSwarmView: React.FC = () => {
  // Mode selection: Swarm vs Classic Fallback Assistant
  const [viewMode, setViewMode] = useState<'swarm' | 'classic'>('swarm');

  // Input state
  const [query, setQuery] = useState('');
  const [workflowMode, setWorkflowMode] = useState<InvestigationWorkflowType>('GENERAL_QUESTION');
  const [targetCve, setTargetCve] = useState('');
  const [targetAsset, setTargetAsset] = useState('');
  const [userRole, setUserRole] = useState('SOC_ANALYST');

  // Swarm runtime execution state
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [streamProgressMessage, setStreamProgressMessage] = useState<string>('');
  const [abortController, setAbortController] = useState<AbortController | null>(null);

  // Agent statuses
  const [agentStatuses, setAgentStatuses] = useState<Record<AgentRoleName, AgentStatusInfo>>({
    orchestrator: { role: 'orchestrator', name: AGENT_METADATA.orchestrator.name, status: 'pending' },
    threat_intel: { role: 'threat_intel', name: AGENT_METADATA.threat_intel.name, status: 'pending' },
    vuln_intel: { role: 'vuln_intel', name: AGENT_METADATA.vuln_intel.name, status: 'pending' },
    asset_risk: { role: 'asset_risk', name: AGENT_METADATA.asset_risk.name, status: 'pending' },
    compliance: { role: 'compliance', name: AGENT_METADATA.compliance.name, status: 'pending' },
    evidence: { role: 'evidence', name: AGENT_METADATA.evidence.name, status: 'pending' },
    verification: { role: 'verification', name: AGENT_METADATA.verification.name, status: 'pending' },
  });

  // Current report results
  const [activeReport, setActiveReport] = useState<InvestigationReport | null>(null);
  const [selectedAgentDetail, setSelectedAgentDetail] = useState<AgentRoleName>('orchestrator');
  const [activeTab, setActiveTab] = useState<'report' | 'agents' | 'evidence' | 'verification' | 'history'>('report');

  // Swarm system status
  const [swarmStatus, setSwarmStatus] = useState<SwarmStatus | null>(null);
  const [isLoadingStatus, setIsLoadingStatus] = useState(false);

  // History state
  const [historyItems, setHistoryItems] = useState<InvestigationHistoryItem[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);

  // Classic assistant fallback state
  const [classicQuery, setClassicQuery] = useState('');
  const [isClassicLoading, setIsClassicLoading] = useState(false);
  const [classicResponse, setClassicResponse] = useState<ClassicAssistantResponse | null>(null);
  const [classicError, setClassicError] = useState<string | null>(null);

  // Client ID for stream cancellation tracking
  const clientIdRef = useRef<string>(`client_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`);

  // Fetch swarm telemetry & history on mount
  useEffect(() => {
    fetchSwarmStatus();
    fetchHistory();
  }, []);

  const fetchSwarmStatus = async () => {
    setIsLoadingStatus(true);
    try {
      const res = await fetch('/api/agents/status');
      if (res.ok) {
        const data = await res.json();
        setSwarmStatus(data);
      }
    } catch (err) {
      console.warn('Failed to load swarm status:', err);
    } finally {
      setIsLoadingStatus(false);
    }
  };

  const fetchHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const res = await fetch('/api/agents/history?limit=30');
      if (res.ok) {
        const data = await res.json();
        setHistoryItems(data);
      }
    } catch (err) {
      console.warn('Failed to load history:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const loadHistoricalInvestigation = async (id: string) => {
    setSelectedHistoryId(id);
    try {
      const res = await fetch(`/api/agents/history/${encodeURIComponent(id)}`);
      if (res.ok) {
        const data = await res.json();
        setActiveReport(data);
        setActiveTab('report');
        // Reset agent statuses to completed from history
        const updated = { ...agentStatuses };
        Object.keys(updated).forEach((key) => {
          const role = key as AgentRoleName;
          updated[role] = {
            ...updated[role],
            status: 'completed',
            message: 'Loaded from auditable persistent record.',
          };
        });
        setAgentStatuses(updated);
      }
    } catch (err) {
      console.error('Failed to load historical record:', err);
    }
  };

  const handleApplyPreset = (preset: (typeof PRESET_QUERIES)[0]) => {
    setQuery(preset.query);
    setWorkflowMode(preset.workflow);
    if (preset.targetCve) setTargetCve(preset.targetCve);
    else setTargetCve('');
    if (preset.targetAsset) setTargetAsset(preset.targetAsset);
    else setTargetAsset('');
  };

  // Start Real-Time Investigation with SSE Stream
  const handleStartInvestigation = async () => {
    if (!query.trim() || isInvestigating) return;

    setIsInvestigating(true);
    setStreamProgressMessage('Connecting to CRISP Supervised Swarm Engine...');
    setActiveReport(null);
    setActiveTab('report');

    // Reset all agents to pending
    const initialStatuses: Record<AgentRoleName, AgentStatusInfo> = {
      orchestrator: { role: 'orchestrator', name: AGENT_METADATA.orchestrator.name, status: 'pending', message: 'Awaiting orchestrator activation' },
      threat_intel: { role: 'threat_intel', name: AGENT_METADATA.threat_intel.name, status: 'pending', message: 'Queued for concurrent execution' },
      vuln_intel: { role: 'vuln_intel', name: AGENT_METADATA.vuln_intel.name, status: 'pending', message: 'Queued for concurrent execution' },
      asset_risk: { role: 'asset_risk', name: AGENT_METADATA.asset_risk.name, status: 'pending', message: 'Queued for concurrent execution' },
      compliance: { role: 'compliance', name: AGENT_METADATA.compliance.name, status: 'pending', message: 'Queued for concurrent execution' },
      evidence: { role: 'evidence', name: AGENT_METADATA.evidence.name, status: 'pending', message: 'Queued for concurrent execution' },
      verification: { role: 'verification', name: AGENT_METADATA.verification.name, status: 'pending', message: 'Awaiting evidence accumulation' },
    };
    setAgentStatuses(initialStatuses);

    const controller = new AbortController();
    setAbortController(controller);

    try {
      const response = await fetch('/api/agents/investigate/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: query.trim(),
          target_cve: targetCve.trim() || null,
          target_asset: targetAsset.trim() || null,
          user_role: userRole,
          client_id: clientIdRef.current,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error('Response body stream is not available');

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('data:')) {
            const rawJson = trimmed.slice(5).trim();
            if (!rawJson) continue;

            try {
              const event = JSON.parse(rawJson);
              handleStreamEvent(event);
            } catch (jsonErr) {
              console.warn('Failed to parse SSE event:', rawJson);
            }
          }
        }
      }

      // Refresh investigation history upon completion
      fetchHistory();
    } catch (err: any) {
      if (err.name === 'AbortError') {
        setStreamProgressMessage('Investigation cancelled by operator.');
      } else {
        console.error('Investigation stream error:', err);
        setStreamProgressMessage(`Investigation encountered an error: ${err.message}`);
        // Mark orchestrator as failed if no report yet
        setAgentStatuses((prev) => ({
          ...prev,
          orchestrator: { ...prev.orchestrator, status: 'failed', error: err.message },
        }));
      }
    } finally {
      setIsInvestigating(false);
      setAbortController(null);
    }
  };

  const handleCancelInvestigation = async () => {
    if (abortController) {
      abortController.abort();
    }
    try {
      await fetch('/api/agents/cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientIdRef.current }),
      });
    } catch (e) {
      console.warn('Cancel call failed:', e);
    }
    setStreamProgressMessage('Investigation halted by user.');
    setIsInvestigating(false);
  };

  const handleStreamEvent = (event: any) => {
    if (!event || !event.type) return;

    switch (event.type) {
      case 'init':
        setStreamProgressMessage('Orchestrator formulating multi-agent plan...');
        break;

      case 'plan_ready':
        setStreamProgressMessage(
          `Plan formulated for ${event.workflow_type}. Active agents: ${event.target_agents?.length || 5}.`
        );
        break;

      case 'agent_status': {
        const { agent, status, message, error, result, verification } = event;
        if (agent && agent in agentStatuses) {
          const role = agent as AgentRoleName;
          setAgentStatuses((prev) => ({
            ...prev,
            [role]: {
              ...prev[role],
              status: status as AgentExecutionStatus,
              message: message || prev[role].message,
              error: error || prev[role].error,
              data: result || verification || prev[role].data,
            },
          }));
        }
        if (message) {
          setStreamProgressMessage(message);
        }
        break;
      }

      case 'stage':
        if (event.message) {
          setStreamProgressMessage(event.message);
        }
        break;

      case 'investigation_complete': {
        setStreamProgressMessage(`Investigation finalized in ${event.duration_ms}ms.`);
        const finalState = event.final_state;
        if (finalState) {
          setActiveReport(finalState);
          // Set all relevant agents to completed
          setAgentStatuses((prev) => {
            const next = { ...prev };
            Object.keys(next).forEach((key) => {
              const r = key as AgentRoleName;
              if (next[r].status === 'running') {
                next[r] = { ...next[r], status: 'completed' };
              }
            });
            return next;
          });
        }
        break;
      }

      case 'error':
        setStreamProgressMessage(`Error: ${event.message}`);
        break;

      default:
        break;
    }
  };

  // Classic AI Assistant handler
  const handleClassicAssistantSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!classicQuery.trim() || isClassicLoading) return;

    setIsClassicLoading(true);
    setClassicError(null);
    setClassicResponse(null);

    try {
      const res = await fetch('/api/agents/classic-assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: classicQuery.trim() }),
      });
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const data = await res.json();
      setClassicResponse(data);
    } catch (err: any) {
      setClassicError(err.message || 'Failed to query classic assistant');
    } finally {
      setIsClassicLoading(false);
    }
  };

  // Helper for risk badge styling
  const getRiskRatingBadge = (rating?: string) => {
    switch (rating) {
      case 'CRITICAL':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'HIGH':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'MEDIUM':
        return 'bg-yellow-950 text-yellow-300 border-yellow-800';
      case 'LOW':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  // Helper for agent status badge styling
  const getAgentStatusBadge = (status: AgentExecutionStatus) => {
    switch (status) {
      case 'running':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950/80 text-amber-300 border border-amber-700/80">
            <RefreshCw className="w-2.5 h-2.5 animate-spin" /> RUNNING
          </span>
        );
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
            <Check className="w-2.5 h-2.5" /> COMPLETED
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950 text-rose-300 border border-rose-800">
            <XCircle className="w-2.5 h-2.5" /> FAILED
          </span>
        );
      case 'skipped':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800/80 text-slate-400 border border-slate-700">
            <MinusCircle className="w-2.5 h-2.5" /> SKIPPED
          </span>
        );
      case 'pending':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-900 text-slate-400 border border-slate-800">
            <Clock className="w-2.5 h-2.5" /> PENDING
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Mode Toggle */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-cyan-500/20">
              <BrainCircuit className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-white">CRISP Agent Swarm 2.0</h1>
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  LangGraph Supervised Swarm
                </span>
                {swarmStatus?.groq_integration?.is_configured ? (
                  <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-emerald-950 text-emerald-400 border border-emerald-800 hidden sm:inline-block">
                    Groq LLM Active
                  </span>
                ) : (
                  <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300 border border-slate-700 hidden sm:inline-block">
                    Deterministic Engine Active
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Autonomous 7-agent supervisory team executing grounded multi-source investigations across CRISP database, NVD, CISA KEV, and ChromaDB.
              </p>
            </div>
          </div>
        </div>

        {/* Primary View Switcher: Agent Swarm vs Classic Assistant */}
        <div className="flex items-center bg-slate-900 p-1 rounded-lg border border-slate-800 shrink-0">
          <button
            onClick={() => setViewMode('swarm')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
              viewMode === 'swarm'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-xs'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BrainCircuit className="w-3.5 h-3.5" />
            <span>Agent Swarm 2.0</span>
          </button>
          <button
            onClick={() => setViewMode('classic')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
              viewMode === 'classic'
                ? 'bg-purple-950 text-purple-300 border border-purple-800/80 shadow-xs'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bot className="w-3.5 h-3.5" />
            <span>Classic Assistant (Fallback)</span>
          </button>
        </div>
      </div>

      {/* =========================================================================
          VIEW MODE 1: CRISP AGENT SWARM 2.0 INVESTIGATION INTERFACE
          ========================================================================= */}
      {viewMode === 'swarm' && (
        <div className="space-y-6">
          {/* Investigation Input Card */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <label className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <Search className="w-3.5 h-3.5 text-cyan-400" />
                <span>1. Investigation Scope &amp; Target Query</span>
              </label>

              {/* Mode Selector */}
              <div className="flex flex-wrap items-center gap-1">
                {(
                  [
                    { id: 'GENERAL_QUESTION', label: 'General Question' },
                    { id: 'ASSET_INVESTIGATION', label: 'Asset Investigation' },
                    { id: 'CVE_INVESTIGATION', label: 'CVE Investigation' },
                    { id: 'EVENT_INVESTIGATION', label: 'Event Telemetry' },
                    { id: 'CRITICAL_FINDING_INVESTIGATION', label: 'Critical Finding' },
                  ] as const
                ).map((mode) => (
                  <button
                    key={mode.id}
                    onClick={() => setWorkflowMode(mode.id)}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                      workflowMode === mode.id
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                        : 'text-slate-400 hover:text-slate-200 bg-slate-950/60 border border-slate-800'
                    }`}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Question Textarea */}
            <div className="relative">
              <textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter investigation question, target asset name, CVE identifier, or incident query..."
                rows={3}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
            </div>

            {/* Target Entities Row & Action Button */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pt-1">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 font-mono text-[11px]">Target CVE:</span>
                  <input
                    type="text"
                    value={targetCve}
                    onChange={(e) => setTargetCve(e.target.value)}
                    placeholder="e.g. CVE-2021-44228"
                    className="bg-transparent text-slate-200 font-mono text-xs focus:outline-none w-32"
                  />
                </div>

                <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 font-mono text-[11px]">Target Asset:</span>
                  <input
                    type="text"
                    value={targetAsset}
                    onChange={(e) => setTargetAsset(e.target.value)}
                    placeholder="e.g. AST-PROD-WEB-01"
                    className="bg-transparent text-slate-200 font-mono text-xs focus:outline-none w-36"
                  />
                </div>

                <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 font-mono text-[11px]">Role:</span>
                  <select
                    value={userRole}
                    onChange={(e) => setUserRole(e.target.value)}
                    className="bg-transparent text-slate-300 font-mono text-xs focus:outline-none"
                  >
                    <option value="SOC_ANALYST">SOC Analyst</option>
                    <option value="CISO">CISO / Executive</option>
                    <option value="AUDITOR">Compliance Auditor</option>
                    <option value="INCIDENT_RESPONDER">Incident Responder</option>
                  </select>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2">
                {isInvestigating ? (
                  <button
                    onClick={handleCancelInvestigation}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-950 hover:bg-rose-900 text-rose-200 border border-rose-800 text-xs font-semibold transition-colors shadow-sm"
                  >
                    <Square className="w-3.5 h-3.5 fill-rose-300" />
                    <span>Cancel Investigation</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStartInvestigation}
                    disabled={!query.trim()}
                    className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold transition-all shadow-md shadow-cyan-600/20 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Start Swarm Investigation</span>
                  </button>
                )}
              </div>
            </div>

            {/* Quick Presets */}
            <div className="pt-2 border-t border-slate-800/60">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-slate-400 mr-1 flex items-center gap-1">
                  <Sliders className="w-3 h-3 text-cyan-400" /> Investigation Presets:
                </span>
                {PRESET_QUERIES.map((preset, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleApplyPreset(preset)}
                    className="px-2 py-0.5 rounded text-[11px] bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 font-mono transition-colors"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Real-time Status Stream Bar */}
          {(isInvestigating || streamProgressMessage) && (
            <div className="rounded-lg border border-cyan-800/50 bg-cyan-950/30 p-3 flex items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2.5 text-cyan-300 font-mono">
                {isInvestigating ? (
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-400 shrink-0" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                )}
                <span>{streamProgressMessage}</span>
              </div>
              {isInvestigating && (
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 shrink-0">
                  Live Execution
                </span>
              )}
            </div>
          )}

          {/* =========================================================================
              AGENT EXECUTION PANEL (Pending, Running, Completed, Failed, Skipped)
              ========================================================================= */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>2. Multi-Agent Swarm Execution Grid</span>
              </h2>
              <span className="text-[11px] text-slate-400">
                Supervisor: <strong className="text-cyan-300 font-mono">LangGraph StateGraph</strong>
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {(Object.keys(agentStatuses) as AgentRoleName[]).map((role) => {
                const info = agentStatuses[role];
                const meta = AGENT_METADATA[role];
                const Icon = meta.icon;
                const isSelected = selectedAgentDetail === role;

                return (
                  <div
                    key={role}
                    onClick={() => setSelectedAgentDetail(role)}
                    className={`cursor-pointer rounded-lg border p-3.5 transition-all text-xs flex flex-col justify-between ${
                      isSelected
                        ? 'border-cyan-500/80 bg-slate-900 shadow-sm'
                        : 'border-slate-800 bg-slate-900/60 hover:bg-slate-900 hover:border-slate-700'
                    }`}
                  >
                    <div className="space-y-2">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <div className={`p-1.5 rounded-md border ${meta.color}`}>
                            <Icon className="w-3.5 h-3.5" />
                          </div>
                          <div>
                            <div className="font-semibold text-slate-200 leading-tight">{meta.name}</div>
                            <div className="text-[10px] font-mono text-slate-400">{role}</div>
                          </div>
                        </div>
                        {getAgentStatusBadge(info.status)}
                      </div>

                      <p className="text-[11px] text-slate-400 line-clamp-2">
                        {info.message || meta.description}
                      </p>
                    </div>

                    {info.error && (
                      <div className="mt-2 text-[10px] text-rose-400 font-mono flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3 shrink-0" />
                        <span className="truncate">{info.error}</span>
                      </div>
                    )}

                    <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                      <span>Click to inspect</span>
                      <ChevronRight className="w-3 h-3 text-slate-500" />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Partial failure notice if applicable */}
          {activeReport?.agent_failures && activeReport.agent_failures.length > 0 && (
            <div className="rounded-lg border border-amber-800 bg-amber-950/40 p-3.5 text-xs text-amber-200 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <strong className="font-semibold">Partial Result Notice:</strong>
                <p className="mt-0.5 text-amber-300/90">
                  The following agent(s) encountered exceptions during concurrent execution:{' '}
                  <span className="font-mono font-bold">{activeReport.agent_failures.join(', ')}</span>.
                  The Orchestrator and Verification agents successfully synthesized bounded findings based on available evidence.
                </p>
              </div>
            </div>
          )}

          {/* =========================================================================
              NAVIGATION TABS: Report, Agent Results, Evidence, Verification, History
              ========================================================================= */}
          <div className="flex border-b border-slate-800 space-x-1 text-xs font-semibold">
            <button
              onClick={() => setActiveTab('report')}
              className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-colors ${
                activeTab === 'report'
                  ? 'border-cyan-500 text-cyan-400 bg-slate-900/50'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Executive Synthesis</span>
              {activeReport && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${getRiskRatingBadge(activeReport.overall_risk_rating)}`}>
                  {activeReport.overall_risk_rating}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('agents')}
              className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-colors ${
                activeTab === 'agents'
                  ? 'border-cyan-500 text-cyan-400 bg-slate-900/50'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-4 h-4" />
              <span>Agent Findings</span>
            </button>

            <button
              onClick={() => setActiveTab('evidence')}
              className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-colors ${
                activeTab === 'evidence'
                  ? 'border-cyan-500 text-cyan-400 bg-slate-900/50'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Database className="w-4 h-4" />
              <span>Evidence Records</span>
              {activeReport?.evidence?.retrieved_documents_count ? (
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-mono">
                  {activeReport.evidence.retrieved_documents_count}
                </span>
              ) : null}
            </button>

            <button
              onClick={() => setActiveTab('verification')}
              className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-colors ${
                activeTab === 'verification'
                  ? 'border-cyan-500 text-cyan-400 bg-slate-900/50'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>Verification &amp; Integrity</span>
              {activeReport?.verification?.verification_status && (
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-teal-950 text-teal-300 border border-teal-800 font-mono">
                  {activeReport.verification.verification_status}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-colors ${
                activeTab === 'history'
                  ? 'border-cyan-500 text-cyan-400 bg-slate-900/50'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <History className="w-4 h-4" />
              <span>Investigation Audit History</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-mono">
                {historyItems.length}
              </span>
            </button>
          </div>

          {/* =========================================================================
              TAB CONTENT 1: CONSOLIDATED FINAL REPORT
              ========================================================================= */}
          {activeTab === 'report' && (
            <div>
              {activeReport ? (
                <div className="space-y-6">
                  {/* Executive Header Box */}
                  <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
                    <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-cyan-400 uppercase font-semibold">
                            Investigation Report
                          </span>
                          <span className="text-xs text-slate-500 font-mono">#{activeReport.investigation_id}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono uppercase">
                            {activeReport.workflow_type}
                          </span>
                        </div>
                        <h3 className="text-lg font-bold text-white mt-1">
                          {activeReport.query}
                        </h3>
                      </div>

                      {/* Multi-Factor Risk Score Gauge */}
                      <div className="flex items-center gap-3 bg-slate-950 px-4 py-3 rounded-lg border border-slate-800 shrink-0">
                        <div className="text-right">
                          <div className="text-[10px] font-mono uppercase text-slate-400">CRISP Risk Score</div>
                          <div className="text-2xl font-extrabold text-white font-mono tabular-nums">
                            {activeReport.overall_risk_score}
                            <span className="text-xs text-slate-500 font-normal"> / 100</span>
                          </div>
                        </div>
                        <div className={`px-2.5 py-1 rounded text-xs font-bold font-mono border ${getRiskRatingBadge(activeReport.overall_risk_rating)}`}>
                          {activeReport.overall_risk_rating}
                        </div>
                      </div>
                    </div>

                    {/* Executive Summary */}
                    <ExecutiveSummaryCard summary={activeReport.executive_summary} />

                    {/* Confirmed Findings vs Hypotheses */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Confirmed Findings */}
                      <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-800/40 space-y-2">
                        <div className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Confirmed Factual Findings ({activeReport.confirmed_findings?.length || 0})</span>
                        </div>
                        {activeReport.confirmed_findings && activeReport.confirmed_findings.length > 0 ? (
                          <ul className="space-y-1.5 text-xs text-slate-200">
                            {activeReport.confirmed_findings.map((f: any, i: number) => {
                              const claimText = typeof f === 'object' && f !== null ? (f.claim || JSON.stringify(f)) : String(f);
                              const sourceType = typeof f === 'object' && f !== null ? f.source_type : null;
                              const sourceId = typeof f === 'object' && f !== null ? f.source_id : null;
                              const sourceUrl = typeof f === 'object' && f !== null ? f.source_url : null;
                              return (
                                <li key={i} className="flex items-start gap-2">
                                  <span className="text-emerald-400 shrink-0 mt-0.5">•</span>
                                  <div className="flex-1">
                                    <span>{claimText}</span>
                                    {(sourceType || sourceId) && (
                                      <span className="ml-2 inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono rounded bg-emerald-950 text-emerald-300 border border-emerald-800/60">
                                        {sourceType && <span>{sourceType}</span>}
                                        {sourceId && <span className="text-emerald-400 font-semibold">[{sourceId}]</span>}
                                        {sourceUrl && (
                                          <a
                                            href={sourceUrl}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-cyan-400 hover:text-cyan-300 underline inline-flex items-center ml-0.5"
                                          >
                                            <ExternalLink className="w-2.5 h-2.5" />
                                          </a>
                                        )}
                                      </span>
                                    )}
                                  </div>
                                </li>
                              );
                            })}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-500 italic">No confirmed findings identified.</p>
                        )}
                      </div>

                      {/* Hypotheses & Working Theories */}
                      <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-800/40 space-y-2">
                        <div className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                          <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
                          <span>Hypotheses &amp; Unconfirmed Inferences ({activeReport.hypotheses?.length || 0})</span>
                        </div>
                        {activeReport.hypotheses && activeReport.hypotheses.length > 0 ? (
                          <ul className="space-y-1.5 text-xs text-slate-200">
                            {activeReport.hypotheses.map((h: any, i: number) => {
                              const hypText = typeof h === 'object' && h !== null ? (h.hypothesis || JSON.stringify(h)) : String(h);
                              const basisText = typeof h === 'object' && h !== null ? h.basis : null;
                              return (
                                <li key={i} className="flex items-start gap-2">
                                  <span className="text-amber-400 shrink-0 mt-0.5">•</span>
                                  <div className="flex-1">
                                    <span>{hypText}</span>
                                    {basisText && (
                                      <p className="text-[11px] text-amber-300/80 font-mono mt-0.5">
                                        Basis: {basisText}
                                      </p>
                                    )}
                                  </div>
                                </li>
                              );
                            })}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-500 italic">Zero unconfirmed hypotheses pending verification.</p>
                        )}
                      </div>
                    </div>

                    {/* NIST CSF 2.0 Mappings Breakdown */}
                    {activeReport.nist_mappings && Object.keys(activeReport.nist_mappings).length > 0 && (
                      <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-3">
                        <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                          <Award className="w-3.5 h-3.5 text-emerald-400" />
                          <span>NIST CSF 2.0 Compliance Control Mappings</span>
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                          {Object.entries(activeReport.nist_mappings).map(([func, controls]) => (
                            <div key={func} className="p-2.5 rounded bg-slate-900 border border-slate-800 text-xs">
                              <div className="font-mono font-bold text-cyan-300 uppercase text-[11px]">{func}</div>
                              <div className="text-[11px] text-slate-400 mt-1">
                                {Array.isArray(controls) ? controls.join(', ') : String(controls)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Prioritized Recommended Actions */}
                    <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2.5">
                      <div className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Actionable Prioritized Recommendations ({activeReport.recommendations?.length || 0})</span>
                      </div>
                      {activeReport.recommendations && activeReport.recommendations.length > 0 ? (
                        <div className="space-y-2">
                          {activeReport.recommendations.map((rec: any, i: number) => {
                            const recText = typeof rec === 'object' && rec !== null ? (rec.action || rec.recommendation || JSON.stringify(rec)) : String(rec);
                            return (
                              <div
                                key={i}
                                className="flex items-start gap-3 p-2.5 rounded bg-slate-900/60 border border-slate-800 text-xs text-slate-200"
                              >
                                <span className="w-5 h-5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 flex items-center justify-center font-mono text-[10px] font-bold shrink-0">
                                  {i + 1}
                                </span>
                                <span>{recText}</span>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <p className="text-xs text-slate-500 italic">No explicit remediations required.</p>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-slate-800 p-12 text-center bg-slate-900/20">
                  <BrainCircuit className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                  <h3 className="text-sm font-semibold text-slate-300">No Active Investigation Executed</h3>
                  <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
                    Enter an investigation question above or pick one of the preset scenarios to trigger the 7-agent supervisory swarm.
                  </p>
                  <button
                    onClick={() => handleApplyPreset(PRESET_QUERIES[0])}
                    className="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold"
                  >
                    Load Sample Log4Shell Triage
                  </button>
                </div>
              )}
            </div>
          )}

          {/* =========================================================================
              TAB CONTENT 2: INDIVIDUAL AGENT RESULTS PANEL
              ========================================================================= */}
          {activeTab === 'agents' && (
            <div className="space-y-4">
              {/* Agent Selector Bar */}
              <div className="flex flex-wrap items-center gap-1.5 p-1.5 rounded-lg bg-slate-900 border border-slate-800">
                {(Object.keys(agentStatuses) as AgentRoleName[]).map((role) => {
                  const meta = AGENT_METADATA[role];
                  const Icon = meta.icon;
                  const isSelected = selectedAgentDetail === role;

                  return (
                    <button
                      key={role}
                      onClick={() => setSelectedAgentDetail(role)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                        isSelected
                          ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{meta.name}</span>
                    </button>
                  );
                })}
              </div>

              {/* Selected Agent Inspector */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-2.5">
                    {React.createElement(AGENT_METADATA[selectedAgentDetail].icon, {
                      className: 'w-5 h-5 text-cyan-400',
                    })}
                    <div>
                      <h3 className="text-sm font-bold text-white">
                        {AGENT_METADATA[selectedAgentDetail].name}
                      </h3>
                      <p className="text-xs text-slate-400">
                        {AGENT_METADATA[selectedAgentDetail].description}
                      </p>
                    </div>
                  </div>
                  <div>{getAgentStatusBadge(agentStatuses[selectedAgentDetail].status)}</div>
                </div>

                {/* Specific Agent Output Renderer */}
                {(() => {
                  const state = activeReport || ({} as any);
                  const threatIntel = state.threat_intel || state.agent_results?.threat_intel;
                  const vulnIntel = state.vuln_intel || state.agent_results?.vuln_intel;
                  const assetRisk = state.asset_risk || state.agent_results?.asset_risk;
                  const compliance = state.compliance || state.agent_results?.compliance;
                  const evidence = state.evidence || state.agent_results?.evidence;
                  const verification = state.verification;

                  if (selectedAgentDetail === 'threat_intel') {
                    if (!threatIntel) return <p className="text-xs text-slate-500 italic">No threat telemetry gathered.</p>;
                    return (
                      <div className="space-y-4 text-xs">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Events Analyzed</span>
                            <div className="text-lg font-bold text-white font-mono">{threatIntel.analyzed_events_count}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Anomalies Detected</span>
                            <div className="text-lg font-bold text-amber-400 font-mono">{threatIntel.detected_anomalies?.length || 0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">MITRE ATT&amp;CK Tactics</span>
                            <div className="text-lg font-bold text-cyan-400 font-mono">{threatIntel.mitre_tactics?.length || 0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Correlated Findings</span>
                            <div className="text-lg font-bold text-rose-400 font-mono">{threatIntel.correlated_findings_count || 0}</div>
                          </div>
                        </div>

                        <div>
                          <strong className="text-slate-300 uppercase tracking-wider text-[11px] block mb-1">
                            MITRE ATT&amp;CK Tactics Identified:
                          </strong>
                          <div className="flex flex-wrap gap-1.5">
                            {(threatIntel.mitre_tactics || []).map((tac: string, i: number) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono text-[11px]">
                                {tac}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div>
                          <strong className="text-slate-300 uppercase tracking-wider text-[11px] block mb-1">
                            Primary Attack Categories:
                          </strong>
                          <div className="flex flex-wrap gap-1.5">
                            {(threatIntel.primary_attack_categories || []).map((cat: string, i: number) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                                {cat}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    );
                  }

                  if (selectedAgentDetail === 'vuln_intel') {
                    if (!vulnIntel) return <p className="text-xs text-slate-500 italic">No vulnerability intel gathered.</p>;
                    return (
                      <div className="space-y-4 text-xs">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">CVEs Assessed</span>
                            <div className="text-lg font-bold text-white font-mono">{vulnIntel.analyzed_cves?.length || 0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">CISA KEV Exploited</span>
                            <div className="text-lg font-bold text-rose-400 font-mono">{vulnIntel.cisa_kev_matches?.length || 0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Max CVSS Score</span>
                            <div className="text-lg font-bold text-amber-400 font-mono">{vulnIntel.max_cvss_score || 0.0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">CWE Weaknesses</span>
                            <div className="text-lg font-bold text-cyan-400 font-mono">{vulnIntel.common_cwe_weaknesses?.length || 0}</div>
                          </div>
                        </div>

                        <div>
                          <strong className="text-slate-300 uppercase tracking-wider text-[11px] block mb-1">
                            Active CISA KEV Matches (Known Exploited):
                          </strong>
                          <div className="flex flex-wrap gap-1.5">
                            {(vulnIntel.cisa_kev_matches || []).length > 0 ? (
                              vulnIntel.cisa_kev_matches.map((cve: string, i: number) => (
                                <span key={i} className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono text-[11px] font-bold">
                                  {cve} (Active In-the-Wild Exploitation)
                                </span>
                              ))
                            ) : (
                              <span className="text-slate-500 italic">None of the analyzed CVEs appear on CISA KEV.</span>
                            )}
                          </div>
                        </div>

                        <div>
                          <strong className="text-slate-300 uppercase tracking-wider text-[11px] block mb-1">
                            Recommended Remediations:
                          </strong>
                          <ul className="space-y-1">
                            {(vulnIntel.actionable_remediations || []).map((rem: string, i: number) => (
                              <li key={i} className="text-slate-300 flex items-start gap-1.5">
                                <span className="text-cyan-400">•</span>
                                <span>{rem}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    );
                  }

                  if (selectedAgentDetail === 'asset_risk') {
                    if (!assetRisk) return <p className="text-xs text-slate-500 italic">No asset risk data gathered.</p>;
                    return (
                      <div className="space-y-4 text-xs">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Evaluated Assets</span>
                            <div className="text-lg font-bold text-white font-mono">{assetRisk.evaluated_assets?.length || 0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Max Criticality</span>
                            <div className="text-lg font-bold text-rose-400 font-mono">{assetRisk.max_criticality || 'NONE'}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Average Risk Score</span>
                            <div className="text-lg font-bold text-amber-400 font-mono">{assetRisk.average_risk_score || 0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Network Exposure</span>
                            <div className="text-lg font-bold text-cyan-400 font-mono">{assetRisk.network_exposures?.length || 0}</div>
                          </div>
                        </div>

                        <div>
                          <strong className="text-slate-300 uppercase tracking-wider text-[11px] block mb-1">
                            Evaluated Enterprise Assets:
                          </strong>
                          <div className="flex flex-wrap gap-1.5">
                            {(assetRisk.evaluated_assets || []).map((ast: string, i: number) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-mono text-[11px]">
                                {ast}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div>
                          <strong className="text-slate-300 uppercase tracking-wider text-[11px] block mb-1">
                            Identified Risk Factors:
                          </strong>
                          <div className="flex flex-wrap gap-1.5">
                            {(assetRisk.risk_factors || []).map((rf: string, i: number) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                                {rf}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    );
                  }

                  if (selectedAgentDetail === 'compliance') {
                    if (!compliance) return <p className="text-xs text-slate-500 italic">No compliance data gathered.</p>;
                    return (
                      <div className="space-y-4 text-xs">
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">NIST Readiness Score</span>
                            <div className="text-lg font-bold text-emerald-400 font-mono">{compliance.compliance_readiness_score || 0}%</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">NIST Functions</span>
                            <div className="text-lg font-bold text-white font-mono">{compliance.evaluated_nist_functions?.length || 0}</div>
                          </div>
                          <div className="p-3 rounded bg-slate-950 border border-slate-800">
                            <span className="text-slate-400">Non-Compliant Gaps</span>
                            <div className="text-lg font-bold text-rose-400 font-mono">{compliance.non_compliant_gaps?.length || 0}</div>
                          </div>
                        </div>

                        <div>
                          <strong className="text-slate-300 uppercase tracking-wider text-[11px] block mb-1">
                            Audit Control Gaps:
                          </strong>
                          <ul className="space-y-1">
                            {(compliance.non_compliant_gaps || []).map((gap: string, i: number) => (
                              <li key={i} className="text-rose-300 flex items-start gap-1.5">
                                <span className="text-rose-400">•</span>
                                <span>{gap}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    );
                  }

                  if (selectedAgentDetail === 'evidence') {
                    if (!evidence) return <p className="text-xs text-slate-500 italic">No evidence data gathered.</p>;
                    return (
                      <div className="space-y-3 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-400">Retrieved Documents: <strong className="text-white font-mono">{evidence.retrieved_documents_count || 0}</strong></span>
                          <span className="text-slate-400 font-mono">Collections: {(evidence.collections_queried || []).join(', ')}</span>
                        </div>
                        <div className="space-y-1.5">
                          {(evidence.citations || []).map((cit: string, i: number) => (
                            <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300">
                              {cit}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  }

                  if (selectedAgentDetail === 'verification') {
                    if (!verification) return <p className="text-xs text-slate-500 italic">No verification executed yet.</p>;
                    return (
                      <div className="space-y-3 text-xs">
                        <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                          <span className="text-slate-400">Verification Integrity Status:</span>
                          <span className="px-2 py-0.5 rounded bg-teal-950 text-teal-300 border border-teal-800 font-mono font-bold">
                            {verification.verification_status}
                          </span>
                        </div>
                        <div className="space-y-1">
                          <strong className="text-slate-400 uppercase text-[10px] block">Audit Rules Checked:</strong>
                          {(verification.audit_trail || []).map((r: any, i: number) => (
                            <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] flex items-center justify-between">
                              <span className="text-slate-300">{r.rule}</span>
                              <span className="font-mono text-emerald-400 font-semibold">{r.status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  }

                  // Orchestrator fallback
                  return (
                    <div className="space-y-3 text-xs">
                      <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                        <span className="text-slate-400 font-mono text-[11px]">Workflow Plan Objective:</span>
                        <p className="text-slate-200">
                          {state.plan?.primary_objective || 'Conduct supervised multi-source cybersecurity investigation.'}
                        </p>
                      </div>
                      <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                        <span className="text-slate-400 font-mono text-[11px]">Target Agents Coordinated:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {(state.plan?.target_agents || []).map((ag: string) => (
                            <span key={ag} className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono text-[11px]">
                              {ag}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          )}

          {/* =========================================================================
              TAB CONTENT 3: EVIDENCE RECORDS PANEL
              ========================================================================= */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-blue-400" />
                    <span>Authoritative Grounded Evidence Records</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Directly retrieved from ChromaDB vector collections and verified SQLite relational tables.
                  </p>
                </div>
              </div>

              {activeReport?.evidence?.retrieved_documents && activeReport.evidence.retrieved_documents.length > 0 ? (
                <div className="space-y-2.5">
                  {activeReport.evidence.retrieved_documents.map((doc, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs space-y-2 hover:border-slate-700 transition-colors"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 font-mono text-[10px]">
                            {doc.collection || 'CRISP_KB'}
                          </span>
                          <span className="font-mono text-cyan-300 font-semibold">{doc.id}</span>
                        </div>
                        {doc.distance !== undefined && (
                          <span className="text-slate-500 font-mono text-[11px]">
                            Cosine Distance: <strong className="text-slate-300 font-mono">{Number(doc.distance).toFixed(3)}</strong>
                          </span>
                        )}
                      </div>

                      <p className="text-slate-300 leading-relaxed font-sans">{doc.document}</p>

                      {/* External reference links if available */}
                      {doc.id && doc.id.startsWith('CVE-') && (
                        <div className="flex items-center gap-3 pt-1 text-[11px]">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${doc.id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 underline"
                          >
                            <span>NVD NIST Record</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                          <a
                            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-rose-400 hover:text-rose-300 flex items-center gap-1 underline"
                          >
                            <span>CISA KEV Catalog</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-slate-500 text-xs">
                  No evidence documents retrieved for this investigation.
                </div>
              )}
            </div>
          )}

          {/* =========================================================================
              TAB CONTENT 4: VERIFICATION & INTEGRITY PANEL
              ========================================================================= */}
          {activeTab === 'verification' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-teal-400" />
                  <span>Verification Agent Claim Integrity &amp; Contradiction Audit</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Automated cross-checking of all factual conclusions against primary records to prevent hallucinations.
                </p>
              </div>

              {activeReport?.verification ? (
                <div className="space-y-4">
                  {/* Contradictions Box */}
                  <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                    <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <AlertCircle className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Contradictions &amp; Inconsistencies</span>
                    </div>
                    {activeReport.verification.contradictions_detected &&
                    activeReport.verification.contradictions_detected.length > 0 ? (
                      <ul className="space-y-1 text-xs text-rose-300">
                        {activeReport.verification.contradictions_detected.map((c: any, i: number) => {
                          const text = typeof c === 'object' && c !== null ? (c.contradiction || c.claim || c.details || JSON.stringify(c)) : String(c);
                          return (
                            <li key={i} className="flex items-start gap-1.5">
                              <span className="text-rose-400 font-bold">•</span>
                              <span>{text}</span>
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <div className="flex items-center gap-2 text-xs text-emerald-400 font-mono">
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Zero contradictions detected across domain agent conclusions.</span>
                      </div>
                    )}
                  </div>

                  {/* Missing Evidence Box */}
                  <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                    <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
                      <span>Missing Evidence Identified</span>
                    </div>
                    {activeReport.verification.missing_evidence &&
                    activeReport.verification.missing_evidence.length > 0 ? (
                      <ul className="space-y-1.5 text-xs text-amber-200">
                        {activeReport.verification.missing_evidence.map((m: any, i: number) => {
                          const itemTitle = typeof m === 'object' && m !== null ? (m.item || JSON.stringify(m)) : String(m);
                          const reason = typeof m === 'object' && m !== null ? m.reason : null;
                          return (
                            <li key={i} className="flex items-start gap-1.5">
                              <span className="text-amber-400">•</span>
                              <div className="flex-1">
                                <span className="font-semibold">{itemTitle}</span>
                                {reason && <p className="text-[11px] text-amber-300/80 mt-0.5">{reason}</p>}
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <div className="text-xs text-slate-400 italic">
                        All factual statements are supported by database or vector records.
                      </div>
                    )}
                  </div>

                  {/* Verification Audit Trail */}
                  <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
                    <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-teal-400" />
                      <span>Integrity Audit Trail Rules</span>
                    </div>
                    <div className="space-y-2">
                      {(activeReport.verification.audit_trail || []).map((rule, idx) => (
                        <div
                          key={idx}
                          className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 p-2.5 rounded bg-slate-950 border border-slate-800 text-xs"
                        >
                          <div>
                            <span className="font-mono text-cyan-300 font-semibold">{rule.rule}</span>
                            <p className="text-slate-400 text-[11px] mt-0.5">{rule.detail}</p>
                          </div>
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] uppercase font-bold shrink-0 ${
                              rule.status === 'PASSED'
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                : 'bg-amber-950 text-amber-300 border border-amber-800'
                            }`}
                          >
                            {rule.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-slate-500 text-xs">
                  Run an investigation to view verification results.
                </div>
              )}
            </div>
          )}

          {/* =========================================================================
              TAB CONTENT 5: INVESTIGATION AUDIT HISTORY
              ========================================================================= */}
          {activeTab === 'history' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-purple-400" />
                    <span>Auditable Investigation History</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Persisted in SQLite database (`investigation_history`) with timestamps and cryptographic IDs.
                  </p>
                </div>
                <button
                  onClick={fetchHistory}
                  disabled={isLoadingHistory}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-mono transition-colors"
                >
                  <RefreshCw className={`w-3 h-3 ${isLoadingHistory ? 'animate-spin text-cyan-400' : ''}`} />
                  <span>Refresh</span>
                </button>
              </div>

              {historyItems.length > 0 ? (
                <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-900/60">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-mono border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-2.5">Timestamp</th>
                        <th className="px-4 py-2.5">Workflow</th>
                        <th className="px-4 py-2.5">Investigation Query</th>
                        <th className="px-4 py-2.5">Risk Rating</th>
                        <th className="px-4 py-2.5">Verification</th>
                        <th className="px-4 py-2.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {historyItems.map((item) => (
                        <tr
                          key={item.investigation_id}
                          className={`hover:bg-slate-900/80 transition-colors ${
                            selectedHistoryId === item.investigation_id ? 'bg-cyan-950/30' : ''
                          }`}
                        >
                          <td className="px-4 py-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                            {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Recent'}
                          </td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                              {item.workflow_type}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-slate-200 max-w-xs truncate" title={item.query}>
                            {item.query}
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getRiskRatingBadge(
                                item.overall_risk_rating
                              )}`}
                            >
                              {item.overall_risk_rating} ({item.overall_risk_score})
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-teal-950 text-teal-300 border border-teal-800">
                              {item.verification_status || 'VERIFIED'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              onClick={() => loadHistoricalInvestigation(item.investigation_id)}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold font-mono transition-colors"
                            >
                              Load Report
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-slate-500 text-xs">
                  No investigation history found in database.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          VIEW MODE 2: CLASSIC AI SECURITY ASSISTANT (Direct RAG Groq Fallback)
          ========================================================================= */}
      {viewMode === 'classic' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-purple-800/60 bg-slate-900/80 p-5 space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-purple-950 text-purple-400 border border-purple-800">
                <Bot className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-bold text-white">Classic AI Security Assistant</h2>
                  <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-purple-950 text-purple-300 border border-purple-800">
                    Direct RAG + Groq Fallback
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Original direct question-and-answer assistant powered by ChromaDB semantic retrieval and Groq LLM completion.
                </p>
              </div>
            </div>

            <form onSubmit={handleClassicAssistantSubmit} className="space-y-3">
              <div className="relative">
                <textarea
                  value={classicQuery}
                  onChange={(e) => setClassicQuery(e.target.value)}
                  placeholder="Ask any cybersecurity, NIST CSF, or CRISP platform question..."
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="text-[11px] text-slate-400">
                  Model: <span className="text-purple-300 font-mono">llama-3.3-70b-versatile</span>
                </div>
                <button
                  type="submit"
                  disabled={!classicQuery.trim() || isClassicLoading}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-900 hover:bg-purple-800 text-purple-100 text-xs font-semibold transition-colors disabled:opacity-50"
                >
                  {isClassicLoading ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Sparkles className="w-3.5 h-3.5" />
                  )}
                  <span>{isClassicLoading ? 'Generating Answer...' : 'Ask Assistant'}</span>
                </button>
              </div>
            </form>

            {classicError && (
              <div className="p-3 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs">
                {classicError}
              </div>
            )}

            {classicResponse && (
              <div className="pt-4 border-t border-slate-800/80 space-y-4">
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 leading-relaxed space-y-2">
                  <div className="text-xs font-bold text-purple-400 uppercase tracking-wider">
                    Assistant Response:
                  </div>
                  <div className="whitespace-pre-line text-xs font-sans text-slate-200">
                    {classicResponse.answer}
                  </div>
                </div>

                {classicResponse.sources && classicResponse.sources.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                      Grounding Context Citations ({classicResponse.sources.length}):
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {classicResponse.sources.map((src, i) => (
                        <div key={i} className="p-2.5 rounded bg-slate-950/70 border border-slate-800 text-xs space-y-1">
                          <div className="font-mono text-[10px] text-cyan-400 font-semibold">{src.id}</div>
                          <p className="text-slate-300 line-clamp-3 text-[11px]">{src.document}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
