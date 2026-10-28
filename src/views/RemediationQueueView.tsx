import React, { useState, useEffect, useCallback } from 'react';
import { useCrisp } from '../context/CrispContext';
import {
  RemediationPlan,
  RemediationStatus,
  RemediationPriority,
  ApprovalStatus,
} from '../types/remediation';
import {
  Wrench,
  ShieldAlert,
  Flame,
  CheckCircle2,
  Clock,
  AlertTriangle,
  RotateCcw,
  RefreshCw,
  Search,
  Filter,
  ExternalLink,
  Bot,
  BrainCircuit,
  Server,
  ArrowRight,
  FileCheck,
  ShieldCheck,
  X,
  Plus,
  Lock,
  Layers,
  ChevronRight,
  Sliders,
  Send,
  Eye,
} from 'lucide-react';

export const RemediationQueueView: React.FC = () => {
  const { setActiveTab } = useCrisp();

  const [plans, setPlans] = useState<RemediationPlan[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState<RemediationPlan | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Modals & Panels
  const [isVerifyModalOpen, setIsVerifyModalOpen] = useState(false);
  const [isAiModalOpen, setIsAiModalOpen] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiCustomQuestion, setAiCustomQuestion] = useState('');

  // Verification Form State
  const [verifyScanner, setVerifyScanner] = useState('Tenable Nessus Agent / SBOM Audit');
  const [verifyScanId, setVerifyScanId] = useState('SCAN-20261028-VERIFY-01');
  const [verifyIsClean, setVerifyIsClean] = useState(true);
  const [verifyEvidenceSummary, setVerifyEvidenceSummary] = useState(
    'Post-remediation vulnerability scan confirmed package upgraded; zero vulnerability signatures detected on target endpoint.'
  );

  // User role for authorization demo (SOC_ANALYST, SECURITY_LEAD, ADMIN)
  const [actingRole, setActingRole] = useState<'SOC_ANALYST' | 'SECURITY_LEAD' | 'ADMIN'>('SOC_ANALYST');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Reopen prompt
  const [reopenReason, setReopenReason] = useState('');
  const [isReopenPromptOpen, setIsReopenPromptOpen] = useState(false);

  // Fetch plans
  const fetchPlans = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusFilter !== 'ALL') params.set('status', statusFilter);
      if (priorityFilter !== 'ALL') params.set('priority', priorityFilter);
      if (searchQuery.trim()) params.set('search', searchQuery.trim());

      const res = await fetch(`/api/remediations?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setPlans(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error('Failed to fetch remediation plans:', err);
    } finally {
      setIsLoading(false);
    }
  }, [statusFilter, priorityFilter, searchQuery]);

  useEffect(() => {
    fetchPlans();
  }, [fetchPlans]);

  // Generate plans for all open findings
  const handleGeneratePlans = async () => {
    setIsLoading(true);
    setActionMessage('Scanning findings and generating deterministic remediation plans...');
    try {
      const res = await fetch('/api/remediations/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': actingRole,
          'x-user-email': 'saifkar98k@gmail.com',
        },
        body: JSON.stringify({ generate_all: true }),
      });
      if (res.ok) {
        setActionMessage('Remediation plans generated and correlated with verified findings.');
        await fetchPlans();
      }
    } catch (err: any) {
      setActionMessage(`Plan generation failed: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Status transition
  const handleUpdateStatus = async (planId: string, newStatus: string, notes?: string) => {
    setActionMessage(`Updating plan status to ${newStatus}...`);
    try {
      const res = await fetch(`/api/remediations/${planId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': actingRole,
          'x-user-email': 'saifkar98k@gmail.com',
        },
        body: JSON.stringify({ status: newStatus, notes }),
      });
      if (res.ok) {
        const updated = await res.json();
        setActionMessage(`Status updated to ${newStatus}.`);
        await fetchPlans();
        if (selectedPlan && selectedPlan.remediation_id === planId) {
          setSelectedPlan(updated);
        }
      } else {
        const err = await res.json();
        setActionMessage(`Error: ${err.details || err.error}`);
      }
    } catch (err: any) {
      setActionMessage(`Error: ${err.message}`);
    }
  };

  // Submit verification
  const handleSubmitVerification = async () => {
    if (!selectedPlan) return;
    setActionMessage('Submitting verification evidence & recalculating residual risk...');
    try {
      const res = await fetch(`/api/remediations/${selectedPlan.remediation_id}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': actingRole,
          'x-user-email': 'saifkar98k@gmail.com',
        },
        body: JSON.stringify({
          evidence: {
            scanner_or_tool: verifyScanner,
            scan_id_or_version: verifyScanId,
            evidence_summary: verifyEvidenceSummary,
            is_clean: verifyIsClean,
            timestamp: new Date().toISOString(),
          },
          notes: verifyIsClean
            ? 'Remediation verified clean via authoritative scan evidence.'
            : 'Verification scan detected remaining vulnerability; reopened.',
        }),
      });

      if (res.ok) {
        const updated = await res.json();
        setSelectedPlan(updated);
        setIsVerifyModalOpen(false);
        setActionMessage(
          verifyIsClean
            ? `Plan RESOLVED! CRISP Risk score reduced by ${updated.risk_reduction || 0} pts.`
            : 'Verification evidence failed. Plan marked REOPENED.'
        );
        await fetchPlans();
      } else {
        const err = await res.json();
        setActionMessage(`Verification failed: ${err.details || err.error}`);
      }
    } catch (err: any) {
      setActionMessage(`Verification error: ${err.message}`);
    }
  };

  // Reopen
  const handleReopen = async () => {
    if (!selectedPlan || !reopenReason.trim()) return;
    try {
      const res = await fetch(`/api/remediations/${selectedPlan.remediation_id}/reopen`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': actingRole,
          'x-user-email': 'saifkar98k@gmail.com',
        },
        body: JSON.stringify({ reason: reopenReason.trim() }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedPlan(updated);
        setIsReopenPromptOpen(false);
        setReopenReason('');
        setActionMessage('Remediation plan marked REOPENED.');
        await fetchPlans();
      }
    } catch (err: any) {
      setActionMessage(`Reopen error: ${err.message}`);
    }
  };

  // AI Assistant Advice
  const handleRunAiAssist = async (plan: RemediationPlan, customQ?: string) => {
    setSelectedPlan(plan);
    setIsAiModalOpen(true);
    setIsAiLoading(true);
    setAiAnalysis(null);
    try {
      const res = await fetch(`/api/remediations/${plan.remediation_id}/ai-assist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: customQ || '' }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiAnalysis(data.analysis || 'No analysis returned.');
      } else {
        setAiAnalysis('AI Remediation Assistant is temporarily unavailable.');
      }
    } catch (e: any) {
      setAiAnalysis(`AI Assistant error: ${e.message}`);
    } finally {
      setIsAiLoading(false);
    }
  };

  // Metrics
  const totalPlans = plans.length;
  const awaitingApproval = plans.filter((p) => p.remediation_status === 'AWAITING_APPROVAL').length;
  const inProgress = plans.filter((p) => p.remediation_status === 'IN_PROGRESS').length;
  const awaitingVerify = plans.filter((p) => p.remediation_status === 'AWAITING_VERIFICATION').length;
  const resolved = plans.filter((p) => p.remediation_status === 'RESOLVED').length;
  const totalRiskReduction = plans
    .filter((p) => p.remediation_status === 'RESOLVED' && p.risk_reduction)
    .reduce((acc, p) => acc + (p.risk_reduction || 0), 0);

  const getPriorityBadge = (p: RemediationPriority) => {
    switch (p) {
      case 'IMMEDIATE':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'HIGH':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'MEDIUM':
        return 'bg-yellow-950/70 text-yellow-300 border-yellow-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadge = (s: RemediationStatus) => {
    switch (s) {
      case 'RESOLVED':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'IN_PROGRESS':
        return 'bg-cyan-950 text-cyan-300 border-cyan-800';
      case 'AWAITING_VERIFICATION':
        return 'bg-indigo-950 text-indigo-300 border-indigo-800';
      case 'AWAITING_APPROVAL':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'REOPENED':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'PLANNED':
        return 'bg-blue-950 text-blue-300 border-blue-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Wrench className="w-5 h-5 text-emerald-400" />
            <h3 className="text-lg font-bold text-white tracking-tight">
              Remediation Intelligence Engine &amp; Lifecycle Operations
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
              CRISP 2.0
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Deterministic prioritization, authoritative vendor patch retrieval, multi-stage approval authorization, and mandatory scanner verification with residual cyber risk recalculation.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Active Role Switcher for Authorization Demonstration */}
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 font-mono">
            <span>Role:</span>
            <select
              value={actingRole}
              onChange={(e) => setActingRole(e.target.value as any)}
              className="bg-transparent text-cyan-300 font-bold focus:outline-none cursor-pointer"
              title="Demonstrates role-based authorization for approval and status changes"
            >
              <option value="SOC_ANALYST" className="bg-slate-900 text-slate-200">SOC_ANALYST</option>
              <option value="SECURITY_LEAD" className="bg-slate-900 text-slate-200">SECURITY_LEAD (Approver)</option>
              <option value="ADMIN" className="bg-slate-900 text-slate-200">ADMIN (Superuser)</option>
            </select>
          </div>

          <button
            onClick={handleGeneratePlans}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition-colors disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Generate Plans from Findings</span>
          </button>

          <button
            onClick={fetchPlans}
            disabled={isLoading}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            title="Refresh remediation plans"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Action feedback message */}
      {actionMessage && (
        <div className="p-3 rounded-lg bg-cyan-950/70 border border-cyan-800 text-xs text-cyan-300 font-mono flex items-center justify-between">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Operational KPI Metric Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">Total Plans</span>
          <div className="text-2xl font-black text-white font-mono mt-0.5">{totalPlans}</div>
          <div className="text-[10px] text-slate-500 font-mono">Active lifecycle</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-amber-400 uppercase tracking-wider font-semibold">Awaiting Approval</span>
          <div className="text-2xl font-black text-amber-300 font-mono mt-0.5">{awaitingApproval}</div>
          <div className="text-[10px] text-slate-500 font-mono">Requires Lead sign-off</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-cyan-400 uppercase tracking-wider font-semibold">In Progress</span>
          <div className="text-2xl font-black text-cyan-300 font-mono mt-0.5">{inProgress}</div>
          <div className="text-[10px] text-slate-500 font-mono">Remediation staged</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
          <span className="text-[10px] text-indigo-400 uppercase tracking-wider font-semibold">Verification Pending</span>
          <div className="text-2xl font-black text-indigo-300 font-mono mt-0.5">{awaitingVerify}</div>
          <div className="text-[10px] text-slate-500 font-mono">Mandatory scan check</div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 col-span-2 sm:col-span-1">
          <span className="text-[10px] text-emerald-400 uppercase tracking-wider font-semibold">Resolved / Mitigated</span>
          <div className="text-2xl font-black text-emerald-300 font-mono mt-0.5">{resolved}</div>
          <div className="text-[10px] text-emerald-400 font-mono font-semibold">
            -{totalRiskReduction.toFixed(1)} pts verified risk
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3 text-xs">
        {/* Status Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-slate-400 text-[11px] font-semibold mr-1">Status:</span>
          {(['ALL', 'OPEN', 'PLANNED', 'AWAITING_APPROVAL', 'IN_PROGRESS', 'AWAITING_VERIFICATION', 'RESOLVED', 'REOPENED'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded-lg text-xs font-mono font-semibold transition-colors ${
                statusFilter === st
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Priority & Search Strip */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="flex items-center gap-3 flex-1">
            <div className="relative min-w-[220px] max-w-sm flex-1">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search plan ID, CVE, asset, or summary..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-slate-400 text-[11px]">Priority:</span>
              <select
                value={priorityFilter}
                onChange={(e) => setPriorityFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none"
              >
                <option value="ALL">All Priorities</option>
                <option value="IMMEDIATE">Immediate</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          <div className="text-slate-500 font-mono text-[11px]">
            Showing {plans.length} remediation plan(s)
          </div>
        </div>
      </div>

      {/* Plans List Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-slate-950 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Remediation ID</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3">Target Asset &amp; CVE</th>
                <th className="py-2.5 px-3">CRISP Risk</th>
                <th className="py-2.5 px-3">Approval</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Residual / Reduction</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {plans.length > 0 ? (
                plans.map((p) => {
                  return (
                    <tr
                      key={p.remediation_id}
                      onClick={() => setSelectedPlan(p)}
                      className="cursor-pointer hover:bg-slate-800/50 transition-colors"
                    >
                      <td className="py-3 px-3 font-mono font-semibold text-slate-200 whitespace-nowrap">
                        {p.remediation_id}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPriorityBadge(p.priority)}`}>
                          {p.priority}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-white">{p.asset_name}</div>
                        <div className="text-[11px] text-cyan-400 font-mono mt-0.5">
                          {p.cve_id || 'Security Finding'}
                        </div>
                      </td>
                      <td className="py-3 px-3 font-mono">
                        <span className="font-bold text-rose-300">{p.current_risk_score}</span>
                        <span className="text-[10px] text-slate-500">/100 ({p.current_severity})</span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap font-mono text-[10px]">
                        <span className={`px-1.5 py-0.5 rounded font-bold border ${
                          p.approval_status === 'APPROVED'
                            ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                            : p.approval_status === 'PENDING_APPROVAL'
                            ? 'bg-amber-950 text-amber-300 border-amber-800'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          {p.approval_status}
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusBadge(p.remediation_status)}`}>
                          {p.remediation_status}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono whitespace-nowrap">
                        {p.remediation_status === 'RESOLVED' && p.post_remediation_risk_score !== null ? (
                          <div className="text-emerald-400 font-bold">
                            {p.post_remediation_risk_score}/100
                            <span className="text-[10px] text-emerald-300 ml-1">(-{p.risk_reduction} pts)</span>
                          </div>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => handleRunAiAssist(p)}
                            className="px-2 py-1 rounded bg-indigo-950/80 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 text-[11px] font-semibold flex items-center gap-1 transition-colors"
                            title="Run AI Remediation Assistant"
                          >
                            <BrainCircuit className="w-3 h-3" />
                            <span>AI Assist</span>
                          </button>
                          <button
                            onClick={() => setSelectedPlan(p)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold transition-colors"
                          >
                            Inspect &rarr;
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-500 font-sans">
                    No remediation plans matching criteria. Click &quot;Generate Plans from Findings&quot; above to create plans from open findings.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Plan Details Modal / Drawer */}
      {selectedPlan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="relative w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
            {/* Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <Wrench className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white font-mono">{selectedPlan.remediation_id}</h3>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPriorityBadge(selectedPlan.priority)}`}>
                      {selectedPlan.priority}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusBadge(selectedPlan.remediation_status)}`}>
                      {selectedPlan.remediation_status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Target: {selectedPlan.asset_name} ({selectedPlan.asset_id}) &bull; Finding: {selectedPlan.finding_id}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleRunAiAssist(selectedPlan)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 text-xs font-semibold"
                >
                  <BrainCircuit className="w-3.5 h-3.5" />
                  <span>AI Advisor</span>
                </button>
                <button
                  onClick={() => setSelectedPlan(null)}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Content Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs font-sans">
              {/* Summary & Risk Banner */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider font-mono">
                  Issue Summary &amp; Exposure Analysis
                </div>
                <p className="text-slate-200 text-sm leading-relaxed">{selectedPlan.summary}</p>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 text-[10px]">CURRENT RISK</span>
                    <div className="text-rose-400 font-bold">{selectedPlan.current_risk_score} / 100 ({selectedPlan.current_severity})</div>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px]">ASSOCIATED CVE</span>
                    <div className="text-amber-300 font-bold">{selectedPlan.cve_id || 'None'}</div>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px]">APPROVAL STATE</span>
                    <div className="text-cyan-300 font-bold">{selectedPlan.approval_status}</div>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px]">ASSIGNED OWNER</span>
                    <div className="text-slate-300 font-semibold">{selectedPlan.assigned_to}</div>
                  </div>
                </div>
              </div>

              {/* Verified Vulnerability Evidence */}
              <div>
                <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <span>Verified Vulnerability Evidence</span>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 font-mono text-[11px]">
                  {selectedPlan.evidence && selectedPlan.evidence.length > 0 ? (
                    selectedPlan.evidence.map((ev, i) => (
                      <div key={i} className="flex items-start gap-2 text-slate-300">
                        <span className="text-cyan-400 font-bold">&bull;</span>
                        <span>{ev}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-slate-500">Correlated security finding logged in CRISP SQLite database.</div>
                  )}
                </div>
              </div>

              {/* Recommended Remediation Steps */}
              <div>
                <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-2">
                  <Wrench className="w-4 h-4 text-emerald-400" />
                  <span>Recommended Remediation Steps</span>
                </div>
                <div className="space-y-2">
                  {selectedPlan.recommended_steps.map((step, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3"
                    >
                      <span className="w-5 h-5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono text-[10px] flex items-center justify-center font-bold shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <p className="text-slate-200 text-xs leading-relaxed font-mono">{step}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Authoritative Vendor Advisories & Source References */}
              <div>
                <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-2">
                  <ExternalLink className="w-4 h-4 text-indigo-400" />
                  <span>Authoritative Vendor Advisories &amp; References</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {selectedPlan.vendor_advisories.map((adv, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3 font-mono text-xs">
                      <div>
                        <div className="font-semibold text-slate-200">{adv.title}</div>
                        {adv.notes && <p className="text-[10px] text-slate-400 mt-0.5">{adv.notes}</p>}
                      </div>
                      {adv.url && (
                        <a
                          href={adv.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-cyan-400 hover:text-cyan-300 text-xs shrink-0 flex items-center gap-1"
                        >
                          Source <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Prerequisites, Blast Radius & Rollback */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Prerequisites & Impact */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider font-mono">
                    Prerequisites &amp; Operational Impact
                  </span>
                  <div className="text-[11px] text-amber-300 font-mono font-semibold">
                    Impact: {selectedPlan.prerequisites?.operational_impact || 'Standard maintenance window.'}
                  </div>
                  <ul className="space-y-1 text-slate-400 text-[11px] font-mono list-disc list-inside">
                    {(selectedPlan.prerequisites?.prerequisites || []).map((pre, idx) => (
                      <li key={idx}>{pre}</li>
                    ))}
                  </ul>
                </div>

                {/* Rollback Procedure */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider font-mono">
                    Rollback Considerations
                  </span>
                  <ul className="space-y-1 text-slate-400 text-[11px] font-mono list-disc list-inside">
                    {selectedPlan.rollback_considerations.map((rb, idx) => (
                      <li key={idx}>{rb}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Verification Checklist */}
              <div>
                <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-2">
                  <FileCheck className="w-4 h-4 text-teal-400" />
                  <span>Post-Remediation Verification Checklist</span>
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  {selectedPlan.verification_steps.map((vs, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs font-mono text-slate-300">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{vs}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Status History Audit Trail */}
              <div>
                <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-2">
                  <Clock className="w-4 h-4 text-slate-400" />
                  <span>Lifecycle Status History Audit Log</span>
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 max-h-48 overflow-y-auto font-mono text-[11px]">
                  {selectedPlan.status_history.map((hist, idx) => (
                    <div key={idx} className="p-2 rounded bg-slate-900 border border-slate-800 flex items-start justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-cyan-300">{hist.new_status}</span>
                          {hist.previous_status && <span className="text-slate-500 text-[10px]">from {hist.previous_status}</span>}
                          <span className="text-slate-500 text-[10px]">&bull; by {hist.updated_by} ({hist.user_role})</span>
                        </div>
                        <p className="text-slate-400 text-[10px] mt-0.5">{hist.notes}</p>
                      </div>
                      <span className="text-[10px] text-slate-500 whitespace-nowrap">
                        {hist.timestamp.split('T')[1]?.substring(0, 8)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Footer Workflow Actions Bar */}
            <div className="px-6 py-4 border-t border-slate-800 bg-slate-950 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <span>Transition Status as <strong className="text-cyan-300">{actingRole}</strong>:</span>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {selectedPlan.remediation_status === 'OPEN' && (
                  <button
                    onClick={() => handleUpdateStatus(selectedPlan.remediation_id, 'PLANNED')}
                    className="px-3 py-1.5 rounded-lg bg-blue-950 hover:bg-blue-900 text-blue-300 border border-blue-800 text-xs font-semibold"
                  >
                    Mark Planned
                  </button>
                )}

                {selectedPlan.remediation_status === 'PLANNED' && selectedPlan.approval_status === 'PENDING_APPROVAL' && (
                  <button
                    onClick={() => handleUpdateStatus(selectedPlan.remediation_id, 'IN_PROGRESS', 'Approved by Security Lead')}
                    className="px-3 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 text-xs font-semibold"
                  >
                    Approve &amp; Start Progress
                  </button>
                )}

                {(selectedPlan.remediation_status === 'PLANNED' || selectedPlan.remediation_status === 'OPEN') && (
                  <button
                    onClick={() => handleUpdateStatus(selectedPlan.remediation_id, 'IN_PROGRESS')}
                    className="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold"
                  >
                    Start In Progress
                  </button>
                )}

                {selectedPlan.remediation_status === 'IN_PROGRESS' && (
                  <button
                    onClick={() => handleUpdateStatus(selectedPlan.remediation_id, 'AWAITING_VERIFICATION')}
                    className="px-3 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 text-xs font-semibold"
                  >
                    Stage for Verification
                  </button>
                )}

                {selectedPlan.remediation_status !== 'RESOLVED' && (
                  <button
                    onClick={() => setIsVerifyModalOpen(true)}
                    className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-xs"
                  >
                    Submit Verification Evidence &rarr;
                  </button>
                )}

                {selectedPlan.remediation_status === 'RESOLVED' && (
                  <button
                    onClick={() => setIsReopenPromptOpen(true)}
                    className="px-3 py-1.5 rounded-lg bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 text-xs font-semibold"
                  >
                    Reopen Plan
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Verification Submission Modal */}
      {isVerifyModalOpen && selectedPlan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-xs">
          <div className="relative w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCheck className="w-5 h-5 text-emerald-400" />
                <h4 className="text-base font-bold text-white">Submit Verification Evidence</h4>
              </div>
              <button onClick={() => setIsVerifyModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Mandatory verification evidence: CRISP strictly prohibits marking remediation complete without authentic scan or package audit evidence. Residual cyber risk is recalculated through the risk engine upon verification.
            </p>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Scanning Tool / Auditor</label>
                <input
                  type="text"
                  value={verifyScanner}
                  onChange={(e) => setVerifyScanner(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Scan Report ID / Package Version Audit</label>
                <input
                  type="text"
                  value={verifyScanId}
                  onChange={(e) => setVerifyScanId(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Evidence Summary / Telemetry Result</label>
                <textarea
                  rows={3}
                  value={verifyEvidenceSummary}
                  onChange={(e) => setVerifyEvidenceSummary(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-white focus:outline-none focus:border-cyan-500 text-xs"
                />
              </div>

              <div className="flex items-center gap-2 p-3 rounded-lg bg-slate-950 border border-slate-800">
                <input
                  type="checkbox"
                  id="verifyCleanCheck"
                  checked={verifyIsClean}
                  onChange={(e) => setVerifyIsClean(e.target.checked)}
                  className="w-4 h-4 rounded text-emerald-600 focus:ring-0 cursor-pointer"
                />
                <label htmlFor="verifyCleanCheck" className="text-xs text-slate-200 cursor-pointer">
                  Confirmed Clean: Target vulnerability confirmed absent / patched
                </label>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setIsVerifyModalOpen(false)}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmitVerification}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-xs"
              >
                Submit &amp; Recalculate Risk
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Explicit Reopen Prompt Modal */}
      {isReopenPromptOpen && selectedPlan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-xs">
          <div className="relative w-full max-w-md bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h4 className="text-base font-bold text-white flex items-center gap-2">
                <RotateCcw className="w-4 h-4 text-rose-400" />
                Reopen Remediation Plan
              </h4>
              <button onClick={() => setIsReopenPromptOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-300">
              Document the reason for reopening this remediation plan (e.g. regression detected, new telemetry signature observed):
            </p>

            <textarea
              rows={3}
              value={reopenReason}
              onChange={(e) => setReopenReason(e.target.value)}
              placeholder="Reason for reopening..."
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-white text-xs focus:outline-none focus:border-cyan-500 font-mono"
            />

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setIsReopenPromptOpen(false)}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleReopen}
                disabled={!reopenReason.trim()}
                className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-xs disabled:opacity-50"
              >
                Confirm Reopen
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Remediation Assistant Modal */}
      {isAiModalOpen && selectedPlan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-xs">
          <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 space-y-4 flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <BrainCircuit className="w-5 h-5 text-indigo-400" />
                <div>
                  <h4 className="text-base font-bold text-white font-mono">
                    AI Remediation Assistant: {selectedPlan.remediation_id}
                  </h4>
                  <span className="text-[11px] text-slate-400 font-mono">
                    Powered by Groq &bull; ChromaDB RAG &bull; CRISP Remediation Agent
                  </span>
                </div>
              </div>
              <button onClick={() => setIsAiModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
              {isAiLoading ? (
                <div className="py-12 flex flex-col items-center justify-center gap-3 text-cyan-400">
                  <RefreshCw className="w-6 h-6 animate-spin" />
                  <span>Synthesizing technical remediation briefing, blast radius, and verification steps...</span>
                </div>
              ) : (
                aiAnalysis
              )}
            </div>

            {/* Follow-up question input */}
            <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
              <input
                type="text"
                placeholder="Ask follow-up (e.g. What are the dependencies? Explain rollback procedure)..."
                value={aiCustomQuestion}
                onChange={(e) => setAiCustomQuestion(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && aiCustomQuestion.trim() && !isAiLoading) {
                    handleRunAiAssist(selectedPlan, aiCustomQuestion.trim());
                    setAiCustomQuestion('');
                  }
                }}
                className="flex-1 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-white text-xs font-mono focus:outline-none focus:border-indigo-500"
              />
              <button
                onClick={() => {
                  if (aiCustomQuestion.trim() && !isAiLoading) {
                    handleRunAiAssist(selectedPlan, aiCustomQuestion.trim());
                    setAiCustomQuestion('');
                  }
                }}
                disabled={isAiLoading || !aiCustomQuestion.trim()}
                className="px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
