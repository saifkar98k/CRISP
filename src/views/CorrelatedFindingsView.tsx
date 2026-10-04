import React, { useState, useEffect, useCallback } from 'react';
import { useCrisp } from '../context/CrispContext';
import { SecurityFinding } from '../types/schemas';
import { DataSourceBadge } from '../components/DataSourceBadge';
import {
  GitMerge,
  ShieldAlert,
  Server,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Info,
  Layers,
  ArrowRight,
  Award,
  Zap,
} from 'lucide-react';

interface CorrelationSummary {
  top_risks: any[];
  top_assets: any[];
  top_vulnerabilities: any[];
}

export const CorrelatedFindingsView: React.FC = () => {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [summary, setSummary] = useState<CorrelationSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isRunningCorrelation, setIsRunningCorrelation] = useState(false);

  // Filters
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [assetFilter, setAssetFilter] = useState<string>('ALL');
  const [cveFilter, setCveFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);

  const fetchFindingsData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [findingsRes, summaryRes] = await Promise.all([
        fetch('/api/correlation/findings?limit=150'),
        fetch('/api/correlation/summary'),
      ]);

      if (findingsRes.ok) {
        const raw = await findingsRes.json();
        const mapped: SecurityFinding[] = raw.map((f: any) => ({
          findingId: f.finding_id,
          timestamp: f.timestamp,
          assetId: f.asset_id,
          assetName: f.asset_name,
          eventId: f.event_id,
          cveId: f.cve_id,
          attackCategory: f.attack_category,
          severity: f.severity,
          cvssScore: f.cvss_score,
          knownExploited: Boolean(f.known_exploited),
          assetCriticality: f.asset_criticality,
          riskScore: f.risk_score,
          riskLevel: f.risk_level,
          nistFunction: f.nist_function,
          evidence: Array.isArray(f.evidence) ? f.evidence : [],
          source: f.source || 'CORRELATED_INTELLIGENCE',
        }));
        setFindings(mapped);
      }

      if (summaryRes.ok) {
        const sumData = await summaryRes.json();
        setSummary(sumData);
      }
    } catch (err) {
      console.error('Failed to load correlated findings:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchFindingsData();
  }, [fetchFindingsData]);

  const handleRunCorrelation = async () => {
    setIsRunningCorrelation(true);
    try {
      const res = await fetch('/api/correlation/run', { method: 'POST' });
      if (res.ok) {
        await fetchFindingsData();
      }
    } catch (err) {
      console.error('Failed to run correlation:', err);
    } finally {
      setIsRunningCorrelation(false);
    }
  };

  // Filtered findings
  const filteredFindings = findings.filter((f) => {
    if (riskFilter !== 'ALL' && f.riskLevel !== riskFilter) return false;
    if (assetFilter !== 'ALL' && f.assetId !== assetFilter) return false;
    if (cveFilter !== 'ALL' && f.cveId !== cveFilter) return false;

    if (search.trim()) {
      const q = search.toLowerCase();
      const matchId = f.findingId.toLowerCase().includes(q);
      const matchAsset = f.assetName?.toLowerCase().includes(q) || f.assetId?.toLowerCase().includes(q);
      const matchCve = f.cveId?.toLowerCase().includes(q);
      const matchCat = f.attackCategory.toLowerCase().includes(q);
      const matchEv = f.evidence.some((e) => e.toLowerCase().includes(q));
      return Boolean(matchId || matchAsset || matchCve || matchCat || matchEv);
    }
    return true;
  });

  const uniqueAssets = Array.from(new Set(findings.map((f) => f.assetId).filter(Boolean))).sort();
  const uniqueCves = Array.from(new Set(findings.map((f) => f.cveId).filter(Boolean))).sort();

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <GitMerge className="w-5 h-5 text-cyan-400" />
              <span>Correlated Security Findings</span>
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800">
              Unified Intelligence
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic correlation connecting Security Events &rarr; Assets &rarr; NVD CVEs &rarr; CISA KEV &rarr; NIST CSF 2.0 with auditable evidence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRunCorrelation}
            disabled={isRunningCorrelation}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRunningCorrelation ? 'animate-spin' : ''}`} />
            <span>{isRunningCorrelation ? 'Executing Correlation...' : 'Run Correlation Engine'}</span>
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Top Correlated Risks */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs font-bold text-slate-300 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Top Correlated Risks
              </span>
              <span className="text-[10px] text-slate-400 font-mono">Ranked by Score</span>
            </div>
            <div className="space-y-2">
              {summary.top_risks.slice(0, 3).map((r: any) => (
                <div
                  key={r.finding_id}
                  onClick={() => {
                    const match = findings.find((f) => f.findingId === r.finding_id);
                    if (match) setSelectedFinding(match);
                  }}
                  className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-white font-bold truncate max-w-[170px]">{r.asset_name || 'Uncorrelated'}</span>
                    <span className="text-rose-400 font-extrabold">{r.risk_score} pts</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1">
                    <span className="truncate max-w-[160px]">{r.attack_category}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800">
                      {r.risk_level}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top Affected Assets */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs font-bold text-slate-300 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <Server className="w-4 h-4 text-cyan-400" />
                Top Affected Assets
              </span>
              <span className="text-[10px] text-slate-400 font-mono">By Findings Count</span>
            </div>
            <div className="space-y-2">
              {summary.top_assets.slice(0, 3).map((a: any) => (
                <div
                  key={a.asset_id}
                  className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1"
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-cyan-300 font-bold">{a.asset_name}</span>
                    <span className="text-slate-300 font-bold">{a.finding_count} findings</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>Criticality: <strong className="text-slate-200">{a.asset_criticality}</strong></span>
                    <span className="text-amber-400 font-mono">Peak: {a.max_risk_score} pts</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top Vulnerabilities Associated with Events */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs font-bold text-slate-300 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Top Event-Linked CVEs
              </span>
              <span className="text-[10px] text-slate-400 font-mono">NVD &amp; CISA KEV</span>
            </div>
            <div className="space-y-2">
              {summary.top_vulnerabilities.length === 0 ? (
                <div className="p-4 rounded bg-slate-950 text-slate-400 text-xs text-center font-sans">
                  No direct CVEs linked in current telemetry batch.
                </div>
              ) : (
                summary.top_vulnerabilities.slice(0, 3).map((v: any) => (
                  <div
                    key={v.cve_id}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-amber-300 font-bold">{v.cve_id}</span>
                      <span className="text-slate-300">{v.event_count} events</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>CVSS: {v.cvss_score || 'N/A'}</span>
                      {v.is_known_exploited && (
                        <span className="text-[10px] px-1 rounded bg-rose-950 text-rose-300 border border-rose-800 font-sans font-bold">
                          CISA KEV
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Filter Correlated Security Findings</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          {/* Risk Level Filter */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Risk Level
            </label>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Asset Filter */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Asset Target
            </label>
            <select
              value={assetFilter}
              onChange={(e) => setAssetFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            >
              <option value="ALL">All Assets</option>
              {uniqueAssets.map((ast) => (
                <option key={ast} value={ast || ''}>
                  {ast}
                </option>
              ))}
            </select>
          </div>

          {/* CVE Filter */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Vulnerability (CVE)
            </label>
            <select
              value={cveFilter}
              onChange={(e) => setCveFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            >
              <option value="ALL">All CVEs</option>
              {uniqueCves.map((cve) => (
                <option key={cve} value={cve || ''}>
                  {cve}
                </option>
              ))}
            </select>
          </div>

          {/* Search Box */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Search Text
            </label>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search finding, asset, CVE..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-bold text-slate-200 uppercase font-mono">
            Correlated Findings: {filteredFindings.length} of {findings.length}
          </span>
          <span className="text-xs text-slate-400">Click any row to view structured evidence trail</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 font-semibold uppercase border-b border-slate-800 font-sans">
              <tr>
                <th className="py-3 px-4">Finding ID</th>
                <th className="py-3 px-4">Correlated Asset</th>
                <th className="py-3 px-4">Vulnerability (CVE)</th>
                <th className="py-3 px-4">Attack Vector</th>
                <th className="py-3 px-4">NIST CSF 2.0</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4 text-right">Risk Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 font-sans text-xs">
                    No correlated findings match the active criteria.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((f) => {
                  const riskColor =
                    f.riskLevel === 'CRITICAL'
                      ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                      : f.riskLevel === 'HIGH'
                      ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                      : f.riskLevel === 'MEDIUM'
                      ? 'bg-yellow-950/80 text-yellow-300 border-yellow-800'
                      : 'bg-emerald-950/80 text-emerald-300 border-emerald-800';

                  return (
                    <tr
                      key={f.findingId}
                      onClick={() => setSelectedFinding(f)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      {/* Finding ID */}
                      <td className="py-3 px-4">
                        <div className="font-bold text-slate-100">{f.findingId}</div>
                        <div className="text-[10px] text-slate-500 font-sans">Event: {f.eventId || 'Telemetry'}</div>
                      </td>

                      {/* Asset */}
                      <td className="py-3 px-4 font-sans">
                        <div className="font-semibold text-slate-200">{f.assetName || 'Uncorrelated Asset'}</div>
                        <div className="text-[10px] text-slate-400 font-mono">
                          {f.assetId ? `Tier: ${f.assetCriticality}` : 'No CMDB link'}
                        </div>
                      </td>

                      {/* CVE */}
                      <td className="py-3 px-4 font-mono text-[11px]">
                        {f.cveId ? (
                          <div className="space-y-0.5">
                            <span className="text-amber-300 font-bold">{f.cveId}</span>
                            {f.knownExploited && (
                              <span className="block text-[9px] px-1 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800 font-sans font-bold w-fit">
                                CISA KEV
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Uncorrelated</span>
                        )}
                      </td>

                      {/* Attack Vector */}
                      <td className="py-3 px-4 font-sans text-slate-300">
                        {f.attackCategory}
                      </td>

                      {/* NIST Function */}
                      <td className="py-3 px-4 font-mono">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300 text-[11px]">
                          {f.nistFunction}
                        </span>
                      </td>

                      {/* Risk Level */}
                      <td className="py-3 px-4">
                        <span className={`inline-block font-sans font-semibold text-[10px] px-2 py-0.5 rounded border ${riskColor}`}>
                          {f.riskLevel}
                        </span>
                      </td>

                      {/* Score */}
                      <td className="py-3 px-4 text-right">
                        <span className="font-bold text-sm text-cyan-300 font-mono">
                          {f.riskScore.toFixed(1)}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Structured Evidence Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">{selectedFinding.findingId}</h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                    {selectedFinding.riskLevel} ({selectedFinding.riskScore} pts)
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">Generated: {selectedFinding.timestamp}</p>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            {/* Finding Attributes */}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase">Target Enterprise Asset</span>
                <div className="font-mono text-cyan-300 font-bold">{selectedFinding.assetName || 'Uncorrelated'}</div>
                <div className="text-[11px] text-slate-400">Criticality: {selectedFinding.assetCriticality}</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase">Public Vulnerability (NVD / CISA)</span>
                <div className="font-mono text-amber-300 font-bold">{selectedFinding.cveId || 'No direct CVE mapped'}</div>
                <div className="text-[11px] text-slate-400">
                  {selectedFinding.knownExploited ? 'Confirmed Active in CISA KEV' : 'CVSS: ' + (selectedFinding.cvssScore || 'N/A')}
                </div>
              </div>
            </div>

            {/* Auditable Evidence List (Required by Spec) */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                Auditable Evidence &amp; Why This Finding Exists:
              </span>
              <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside">
                {selectedFinding.evidence.map((ev, idx) => (
                  <li key={idx} className="leading-relaxed">
                    <span className="text-slate-200">{ev}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* NIST Remediation Context */}
            <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-900/60 text-xs text-cyan-200 flex items-center justify-between">
              <div>
                <span className="font-bold">NIST CSF 2.0 Function: {selectedFinding.nistFunction}</span>
                <p className="text-[11px] text-cyan-300/80 mt-0.5">
                  Prioritize continuous monitoring and response containment for Tier-1 assets.
                </p>
              </div>
              <Award className="w-5 h-5 text-cyan-400" />
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
