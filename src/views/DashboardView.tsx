import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { MetricCard } from '../components/MetricCard';
import { DataSourceBadge } from '../components/DataSourceBadge';
import { RiskBreakdownModal } from '../components/RiskBreakdownModal';
import { RiskEngine } from '../engines/riskEngine';
import { RiskScoreBreakdown, Asset } from '../types/schemas';
import { NvdSyncWidget } from '../components/NvdSyncWidget';
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
} from 'lucide-react';

export const DashboardView: React.FC = () => {
  const {
    vulnerabilities,
    securityEvents,
    assets,
    complianceSummary,
    refreshIntelligence,
    simulateSingleEvent,
    isSyncing,
    setActiveTab,
    provenanceFilter,
  } = useCrisp();

  const [selectedBreakdown, setSelectedBreakdown] = useState<RiskScoreBreakdown | null>(null);

  // Compute metrics
  const realCveCount = vulnerabilities.filter((v) => v.isRealData).length;
  const cisaKevExploitedCount = vulnerabilities.filter((v) => v.isKnownExploited).length;
  const realHistoricalEvents = securityEvents.filter((e) => e.isRealData).length;
  const syntheticDemoEvents = securityEvents.filter((e) => !e.isRealData).length;

  const highestRiskAsset = [...assets].sort((a, b) => b.calculatedRiskScore - a.calculatedRiskScore)[0];

  // Filter events based on active provenance filter
  const displayedEvents = securityEvents.filter((e) => {
    if (provenanceFilter === 'REAL_ONLY') return e.isRealData;
    if (provenanceFilter === 'SYNTHETIC_ONLY') return !e.isRealData;
    return true;
  });

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
      {/* Top Welcome & Streamlit Action Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            Cyber Risk Operations &amp; Intelligence Overview
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time correlation of NVD 2.0 CVE intelligence, CISA KEV exploitation catalogs, and organizational incident telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => refreshIntelligence(true)}
            disabled={isSyncing}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>Sync Vulnerability Intelligence</span>
          </button>
          <button
            onClick={simulateSingleEvent}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-purple-700 hover:bg-purple-600 text-white text-xs font-semibold shadow transition-colors"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Simulate Incident</span>
          </button>
        </div>
      </div>

      {/* NVD Synchronization Section */}
      <NvdSyncWidget />

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3.5">
        <MetricCard
          label="NVD Vulnerabilities"
          value={realCveCount}
          delta={{ value: 'Live 2.0 API', neutral: true }}
          subtitle="Real public CVE records"
          icon={ShieldAlert}
          sourceOrigin="NVD_API"
        />

        <MetricCard
          label="CISA KEV Exploits"
          value={cisaKevExploitedCount}
          delta={{ value: '+3.5x Multiplier', isPositive: false }}
          subtitle="Known exploited in wild"
          icon={Flame}
          sourceOrigin="CISA_KEV"
          alert={cisaKevExploitedCount > 0}
        />

        <MetricCard
          label="Enterprise Assets"
          value={assets.length}
          subtitle="Criticality mapped"
          icon={Server}
        />

        <MetricCard
          label="Historical Incidents"
          value={realHistoricalEvents}
          delta={{ value: 'Real CSV', isPositive: true }}
          subtitle="Normalized SOC events"
          icon={Activity}
          sourceOrigin="HISTORICAL_DATASET"
        />

        <MetricCard
          label="Synthetic Demo Evts"
          value={syntheticDemoEvents}
          delta={{ value: 'Controlled', neutral: true }}
          subtitle="Simulated demo events"
          icon={Zap}
          sourceOrigin="SYNTHETIC_DEMO"
        />

        <MetricCard
          label="NIST CSF 2.0 Score"
          value={complianceSummary ? `${complianceSummary.overallCompliancePct}%` : '78%'}
          delta={{
            value: complianceSummary && complianceSummary.overallCompliancePct >= 80 ? 'Compliant' : 'Needs Review',
            isPositive: complianceSummary ? complianceSummary.overallCompliancePct >= 80 : false,
          }}
          subtitle="Continuous assessment"
          icon={Award}
          sourceOrigin="CRISP_DERIVED"
        />
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Asset Cyber Risk Rankings */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>Enterprise Asset Risk Rankings</span>
                <DataSourceBadge origin="CRISP_DERIVED" size="sm" />
              </h3>
              <p className="text-xs text-slate-400">
                Composite scoring combining CVSS, CISA KEV exploitation, asset tier, and telemetry frequency.
              </p>
            </div>
            <button
              onClick={() => setActiveTab('risk')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-0.5 font-medium"
            >
              View Full Matrix <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {assets.slice(0, 5).map((asset) => {
              const isHigh = asset.calculatedRiskScore >= 8.0;
              const isMed = asset.calculatedRiskScore >= 5.0 && asset.calculatedRiskScore < 8.0;

              return (
                <div
                  key={asset.id}
                  className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-slate-700 transition-colors flex items-center justify-between gap-4"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-xs text-slate-100 truncate">{asset.name}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded font-mono bg-slate-800 text-slate-400">
                        {asset.ipAddress}
                      </span>
                      <span
                        className={`text-[10px] px-1.5 py-0.2 rounded font-bold uppercase ${
                          asset.criticality === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}
                      >
                        {asset.criticality}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-3">
                      <span>Type: {asset.type}</span>
                      <span>Exposure: {asset.exposure}</span>
                      <span>CVEs: {asset.vulnerabilityCount}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <div className="text-xs text-slate-400">CRISP Risk</div>
                      <div
                        className={`font-mono font-extrabold text-base ${
                          isHigh ? 'text-rose-400' : isMed ? 'text-amber-400' : 'text-emerald-400'
                        }`}
                      >
                        {asset.calculatedRiskScore.toFixed(1)} / 10
                      </div>
                    </div>
                    <button
                      onClick={() => handleInspectAsset(asset)}
                      title="Inspect Transparent Factor Formula"
                      className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 border border-slate-700 transition-colors"
                    >
                      <Calculator className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Live Telemetry Stream */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4 flex flex-col">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <span>Security Events Telemetry</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              </h3>
              <p className="text-xs text-slate-400">
                Displaying real historical dataset &amp; synthetic live demo events.
              </p>
            </div>
            <button
              onClick={() => setActiveTab('events')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-0.5 font-medium"
            >
              All Events <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2 flex-1 overflow-y-auto max-h-[380px] pr-1">
            {displayedEvents.slice(0, 6).map((evt) => (
              <div
                key={evt.id}
                className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800 text-xs space-y-1 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 font-mono text-[11px]">
                    <span className="font-semibold text-slate-300">{evt.id}</span>
                    <span className="text-slate-500">•</span>
                    <span className="text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <DataSourceBadge origin={evt.dataSource} isRealData={evt.isRealData} size="sm" />
                </div>

                <div className="font-medium text-slate-200 line-clamp-1">{evt.description}</div>

                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-0.5">
                  <span className="font-mono text-cyan-400">{evt.sourceIp} → {evt.destinationIp}</span>
                  <span
                    className={`font-semibold uppercase text-[10px] px-1.5 py-0.2 rounded ${
                      evt.severity === 'CRITICAL'
                        ? 'bg-rose-950 text-rose-300'
                        : evt.severity === 'HIGH'
                        ? 'bg-amber-950 text-amber-300'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {evt.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* CISA KEV Exploitation Priority Callout */}
      {cisaKevExploitedCount > 0 && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-rose-900/50 text-rose-300 border border-rose-700/50 mt-0.5">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-bold text-rose-200">
                  CISA Binding Operational Directive Warning: {cisaKevExploitedCount} Active Weaponized CVEs
                </h4>
                <DataSourceBadge origin="CISA_KEV" size="sm" />
              </div>
              <p className="text-xs text-rose-300/80 mt-1">
                Active exploits detected in the wild. Risk Engine automatically applies a +2.50 to +3.50 severity booster and updates NIST Protect (PR.PS-01) compliance scores.
              </p>
            </div>
          </div>
          <button
            onClick={() => setActiveTab('vulnerabilities')}
            className="px-3.5 py-2 rounded-lg bg-rose-800 hover:bg-rose-700 text-white text-xs font-semibold shrink-0 transition-colors shadow"
          >
            Review KEV Remediation Dates
          </button>
        </div>
      )}

      {/* Transparent Formula Modal */}
      <RiskBreakdownModal breakdown={selectedBreakdown} onClose={() => setSelectedBreakdown(null)} />
    </div>
  );
};
