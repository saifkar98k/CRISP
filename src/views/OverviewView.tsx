import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { MetricCard } from '../components/MetricCard';
import { DataSourceBadge } from '../components/DataSourceBadge';
import { RiskBreakdownModal } from '../components/RiskBreakdownModal';
import { RiskEngine } from '../engines/riskEngine';
import { RiskScoreBreakdown, Asset } from '../types/schemas';
import {
  ShieldAlert,
  Flame,
  Server,
  Activity,
  Award,
  ChevronRight,
  Calculator,
  RefreshCw,
  Zap,
  ArrowUpRight,
  ShieldCheck,
  AlertTriangle,
  GitMerge,
  CheckCircle2,
  BrainCircuit,
  Radio,
  Clock,
  Layers,
  Database,
  SlidersHorizontal,
} from 'lucide-react';

export const OverviewView: React.FC = () => {
  const {
    vulnerabilities,
    securityEvents,
    assets,
    complianceSummary,
    dataSources,
    lastDataUpdate,
    setActiveTab,
    setSubTab,
  } = useCrisp();

  const [selectedBreakdown, setSelectedBreakdown] = useState<RiskScoreBreakdown | null>(null);

  // Computations
  const realCveCount = vulnerabilities.filter((v) => v.isRealData).length;
  const cisaKevExploitedCount = vulnerabilities.filter((v) => v.isKnownExploited).length;
  const criticalVulnCount = vulnerabilities.filter((v) => v.cvssScore >= 9.0).length;
  const criticalEventsCount = securityEvents.filter((e) => e.severity === 'CRITICAL').length;

  // Composite Risk Score
  const highRiskAssets = [...assets].sort((a, b) => b.calculatedRiskScore - a.calculatedRiskScore);
  const highestRiskAsset = highRiskAssets[0];
  const avgAssetRisk = assets.length > 0
    ? (assets.reduce((acc, a) => acc + a.calculatedRiskScore, 0) / assets.length) * 10
    : 45;
  const compositeRiskScore = Math.min(100, Math.round(avgAssetRisk * 1.1 + (cisaKevExploitedCount > 0 ? 15 : 0)));

  // NIST CSF %
  const nistPercent = complianceSummary?.overallCompliancePct ?? 78.4;

  const handleInspectAsset = (asset: Asset) => {
    const matchedVulns = vulnerabilities.filter((v) => {
      const assetName = asset.name.toLowerCase();
      if (assetName.includes('web') && v.affectedProducts.some((p) => p.toLowerCase().includes('log4j') || p.toLowerCase().includes('struts') || p.toLowerCase().includes('spring'))) return true;
      if (assetName.includes('vpn') && v.affectedProducts.some((p) => p.toLowerCase().includes('citrix') || p.toLowerCase().includes('ivanti') || p.toLowerCase().includes('palo alto'))) return true;
      if (assetName.includes('db') && v.affectedProducts.some((p) => p.toLowerCase().includes('moveit') || p.toLowerCase().includes('sql'))) return true;
      if (assetName.includes('dc') && v.affectedProducts.some((p) => p.toLowerCase().includes('windows') || p.toLowerCase().includes('active directory'))) return true;
      return false;
    });

    const breakdown = RiskEngine.calculateAssetRisk(asset, matchedVulns, securityEvents);
    setSelectedBreakdown(breakdown);
  };

  return (
    <div className="space-y-6">
      {/* Top Executive Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-white tracking-tight">
              Executive Cybersecurity Posture &amp; Risk Overview
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
              SOC DASHBOARD
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Unified threat telemetry, real NVD 2.0 CVE intelligence, CISA Known Exploited Vulnerabilities (KEV), and NIST CSF 2.0 governance metrics.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setActiveTab('swarm')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-950 transition-colors"
          >
            <BrainCircuit className="w-3.5 h-3.5" />
            <span>AI Swarm Investigation</span>
          </button>
          <button
            onClick={() => setActiveTab('live')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold shadow transition-colors"
          >
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            <span>Live Telemetry</span>
          </button>
        </div>
      </div>

      {/* 4 Core Executive Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Composite Risk Score */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Overall CRISP Risk</span>
            <Calculator className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-rose-400 font-mono">
              {compositeRiskScore}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 uppercase font-mono">
              Elevated
            </span>
          </div>
          {/* Risk Gauge Bar */}
          <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${compositeRiskScore}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] text-slate-400 font-mono">
            <span>Trend: +3.2% (7d)</span>
            <button
              onClick={() => {
                setActiveTab('intelligence');
                setSubTab('risk_matrix');
              }}
              className="text-cyan-400 hover:underline flex items-center gap-0.5"
            >
              Matrix &rarr;
            </button>
          </div>
        </div>

        {/* Card 2: NIST CSF 2.0 Compliance */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">NIST CSF 2.0 Score</span>
            <Award className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-emerald-400 font-mono">
              {nistPercent.toFixed(1)}%
            </span>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 uppercase font-mono">
              Tier 3 Repeatable
            </span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${nistPercent}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] text-slate-400 font-mono">
            <span>6 Core Functions</span>
            <button
              onClick={() => {
                setActiveTab('intelligence');
                setSubTab('compliance');
              }}
              className="text-cyan-400 hover:underline flex items-center gap-0.5"
            >
              Controls &rarr;
            </button>
          </div>
        </div>

        {/* Card 3: Vulnerability & KEV Stats */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Vulnerability Intelligence</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-white font-mono">
              {vulnerabilities.length}
            </span>
            <span className="text-xs text-slate-400 font-mono">CVEs tracked</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono font-bold text-[10px]">
              {cisaKevExploitedCount} CISA KEV
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono font-bold text-[10px]">
              {criticalVulnCount} CVSS &ge; 9.0
            </span>
          </div>
          <div className="flex justify-between text-[11px] text-slate-400 font-mono">
            <span>Real NVD 2.0 API</span>
            <button
              onClick={() => {
                setActiveTab('intelligence');
                setSubTab('vulnerabilities');
              }}
              className="text-cyan-400 hover:underline flex items-center gap-0.5"
            >
              Catalog &rarr;
            </button>
          </div>
        </div>

        {/* Card 4: Security Events & Telemetry */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Incident Telemetry</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-cyan-300 font-mono">
              {securityEvents.length}
            </span>
            <span className="text-xs text-slate-400 font-mono">logged events</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800 font-mono font-bold text-[10px]">
              {criticalEventsCount} Critical
            </span>
            <span className="text-slate-400 text-[11px]">CIC-IDS2017 &amp; Live</span>
          </div>
          <div className="flex justify-between text-[11px] text-slate-400 font-mono">
            <span>Auto-correlated</span>
            <button
              onClick={() => setActiveTab('live')}
              className="text-cyan-400 hover:underline flex items-center gap-0.5"
            >
              Monitor &rarr;
            </button>
          </div>
        </div>
      </div>

      {/* Middle Two-Column Grid: Prioritized Findings & Highest-Risk Assets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Correlated High & Critical Findings */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Prioritized Security Findings
              </h3>
            </div>
            <button
              onClick={() => {
                setActiveTab('intelligence');
                setSubTab('findings');
              }}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              View All &rarr;
            </button>
          </div>

          <div className="space-y-2.5">
            {vulnerabilities.filter(v => v.isKnownExploited || v.cvssScore >= 8.5).slice(0, 4).map((vuln) => (
              <div
                key={vuln.id}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 transition-colors flex items-start justify-between gap-3"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono font-bold text-white text-xs">{vuln.id}</span>
                    {vuln.isKnownExploited && (
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-rose-950 text-rose-300 border border-rose-800 font-mono">
                        CISA KEV EXPLOITED
                      </span>
                    )}
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-950 text-amber-300 border border-amber-800 font-mono">
                      CVSS {vuln.cvssScore}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 line-clamp-1">{vuln.description}</p>
                  <div className="text-[11px] text-slate-500 font-mono">
                    Affects: {vuln.affectedProducts.slice(0, 2).join(', ') || 'Enterprise Systems'}
                  </div>
                </div>

                <button
                  onClick={() => setActiveTab('swarm')}
                  className="px-2.5 py-1 rounded bg-indigo-950/80 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 text-[11px] font-semibold shrink-0 transition-colors"
                  title="Launch Swarm Investigation for this CVE"
                >
                  Investigate
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Highest-Risk Assets */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Highest-Risk Enterprise Assets
              </h3>
            </div>
            <button
              onClick={() => {
                setActiveTab('intelligence');
                setSubTab('assets');
              }}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              Inventory &rarr;
            </button>
          </div>

          <div className="space-y-2.5">
            {highRiskAssets.slice(0, 4).map((asset) => {
              const riskColor = asset.calculatedRiskScore >= 7.5
                ? 'text-rose-400 bg-rose-950/60 border-rose-800'
                : asset.calculatedRiskScore >= 5.0
                ? 'text-amber-400 bg-amber-950/60 border-amber-800'
                : 'text-emerald-400 bg-emerald-950/60 border-emerald-800';

              return (
                <div
                  key={asset.id}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 transition-colors flex items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-200 text-xs">{asset.name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {asset.criticality}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono hidden sm:inline">
                        {asset.ipAddress}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-3">
                      <span>Crit: {asset.criticality}</span>
                      <span>Owner: {asset.owner}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${riskColor}`}>
                      {asset.calculatedRiskScore.toFixed(1)}
                    </span>
                    <button
                      onClick={() => handleInspectAsset(asset)}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-semibold transition-colors"
                      title="Inspect transparent formula breakdown"
                    >
                      Formula
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom Grid: Recent Security Events & Data Source Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Events (2 Cols) */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Recent Security Events Telemetry
              </h3>
            </div>
            <button
              onClick={() => setActiveTab('live')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              Live Telemetry Stream &rarr;
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-2 px-3">Time</th>
                  <th className="py-2 px-3">Category</th>
                  <th className="py-2 px-3">Source IP</th>
                  <th className="py-2 px-3">Target</th>
                  <th className="py-2 px-3">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 font-mono">
                {securityEvents.slice(0, 5).map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                      {evt.timestamp.split('T')[1]?.substring(0, 8) || evt.timestamp}
                    </td>
                    <td className="py-2 px-3 font-sans font-medium text-slate-200">
                      {evt.attackCategory}
                    </td>
                    <td className="py-2 px-3 text-cyan-300">
                      {evt.sourceIp || '—'}
                    </td>
                    <td className="py-2 px-3 text-slate-300">
                      {evt.destinationIp || evt.assetId || '—'}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        evt.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : evt.severity === 'HIGH'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-slate-800 text-slate-300'
                      }`}>
                        {evt.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Data Source Health & Synchronization (1 Col) */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Data Sources &amp; Health
              </h3>
            </div>
            <button
              onClick={() => {
                setActiveTab('admin');
                setSubTab('sources');
              }}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              Manage &rarr;
            </button>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">NVD API 2.0 CVEs</div>
                <div className="text-[10px] text-slate-400 font-mono">Sync: Operational</div>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">CISA KEV Catalog</div>
                <div className="text-[10px] text-slate-400 font-mono">Sync: Operational</div>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">CIC-IDS2017 Telemetry</div>
                <div className="text-[10px] text-slate-400 font-mono">Dataset Loaded</div>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">WebAssembly SQLite</div>
                <div className="text-[10px] text-slate-400 font-mono">Read/Write Local DB</div>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
            </div>

            <div className="pt-2 text-[11px] text-slate-400 flex items-center justify-between font-mono">
              <span>Last Sync Check:</span>
              <span className="text-cyan-400">{lastDataUpdate.includes('T') ? lastDataUpdate.split('T')[1]?.substring(0, 8) : lastDataUpdate}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Transparent Risk Breakdown Modal */}
      {selectedBreakdown && (
        <RiskBreakdownModal
          breakdown={selectedBreakdown}
          onClose={() => setSelectedBreakdown(null)}
        />
      )}
    </div>
  );
};
