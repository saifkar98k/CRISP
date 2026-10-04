import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { Vulnerability, RiskScoreBreakdown } from '../types/schemas';
import { DataSourceBadge } from '../components/DataSourceBadge';
import { RiskBreakdownModal } from '../components/RiskBreakdownModal';
import { NvdSyncWidget } from '../components/NvdSyncWidget';
import { RiskEngine } from '../engines/riskEngine';
import {
  Search,
  Flame,
  ExternalLink,
  Calendar,
  AlertOctagon,
  Clock,
  Filter,
  CheckCircle2,
  RefreshCw,
  Info,
} from 'lucide-react';

export const VulnerabilitiesView: React.FC = () => {
  const {
    vulnerabilities,
    refreshIntelligence,
    isSyncing,
    searchQuery,
    setSearchQuery,
    provenanceFilter,
  } = useCrisp();

  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [kevOnly, setKevOnly] = useState<boolean>(false);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [selectedBreakdown, setSelectedBreakdown] = useState<RiskScoreBreakdown | null>(null);
  const [customCveQuery, setCustomCveQuery] = useState('');

  // Filtering
  const filtered = vulnerabilities.filter((v) => {
    if (provenanceFilter === 'REAL_ONLY' && !v.isRealData) return false;
    if (provenanceFilter === 'SYNTHETIC_ONLY' && v.isRealData) return false;
    if (kevOnly && !v.isKnownExploited) return false;
    if (severityFilter !== 'ALL' && v.severity !== severityFilter) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = v.id.toLowerCase().includes(q);
      const matchTitle = v.title.toLowerCase().includes(q);
      const matchDesc = v.description.toLowerCase().includes(q);
      const matchProduct = v.affectedProducts.some((p) => p.toLowerCase().includes(q));
      const matchVendor = v.kevVendorProject?.toLowerCase().includes(q);
      return matchId || matchTitle || matchDesc || matchProduct || matchVendor;
    }

    return true;
  });

  const handleInspectRisk = (v: Vulnerability, e: React.MouseEvent) => {
    e.stopPropagation();
    const breakdown = RiskEngine.calculateVulnerabilityRisk(v);
    setSelectedBreakdown(breakdown);
  };

  const handleSearchNvdApi = async () => {
    if (!customCveQuery.trim()) return;
    setSearchQuery(customCveQuery);
    await refreshIntelligence(true);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-xl font-bold text-white tracking-tight">
              Vulnerability Intelligence (NVD 2.0 Integration)
            </h2>
            <DataSourceBadge origin="NVD_API" size="sm" />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real vulnerability intelligence retrieved directly from the NIST NVD 2.0 API and stored in SQLite.
          </p>
        </div>
      </div>

      {/* NVD Status and Sync Widget */}
      <NvdSyncWidget />

      {/* Search & Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-col lg:flex-row gap-3">
          {/* Main Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by CVE ID (e.g. CVE-2024-3400), description, CWE, or product..."
              className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Quick Query by Specific CVE from NIST */}
          <div className="flex gap-2">
            <input
              type="text"
              value={customCveQuery}
              onChange={(e) => setCustomCveQuery(e.target.value)}
              placeholder="Fetch CVE ID from NVD..."
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-cyan-300 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-48"
            />
            <button
              onClick={handleSearchNvdApi}
              disabled={isSyncing || !customCveQuery.trim()}
              className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold disabled:opacity-40"
            >
              Fetch
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-slate-400 font-medium flex items-center gap-1">
              <Filter className="w-3.5 h-3.5 text-slate-400" /> Severity:
            </span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                  severityFilter === s
                    ? 'bg-slate-800 text-cyan-300 border border-slate-600'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-mono">
              Showing {filtered.length} of {vulnerabilities.length} vulnerabilities
            </span>
          </div>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-semibold border-b border-slate-800 font-sans">
              <tr>
                <th className="py-3 px-3">CVE ID</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3 font-mono">CVSS</th>
                <th className="py-3 px-3">Description</th>
                <th className="py-3 px-3">Published</th>
                <th className="py-3 px-3">Modified</th>
                <th className="py-3 px-3">CWE</th>
                <th className="py-3 px-3 text-right">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    No vulnerabilities matching current filters. Click "Sync NVD" above to fetch from NVD API.
                  </td>
                </tr>
              ) : (
                filtered.map((v) => {
                  const isCrit = v.severity === 'CRITICAL';
                  const isHigh = v.severity === 'HIGH';
                  const isMed = v.severity === 'MEDIUM';

                  return (
                    <tr
                      key={v.id}
                      onClick={() => setSelectedVuln(v)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      {/* 1. CVE ID */}
                      <td className="py-3 px-3 font-mono font-bold text-cyan-300 whitespace-nowrap">
                        {v.id}
                      </td>

                      {/* 2. Severity */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span
                          className={`font-semibold uppercase text-[10px] px-2 py-0.5 rounded font-mono ${
                            isCrit
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : isHigh
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : isMed
                              ? 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {v.severity || 'NONE'}
                        </span>
                      </td>

                      {/* 3. CVSS */}
                      <td className="py-3 px-3 font-mono font-extrabold text-sm whitespace-nowrap">
                        {typeof v.cvssScore === 'number' && v.cvssScore > 0 ? (
                          <span
                            className={
                              isCrit ? 'text-rose-400' : isHigh ? 'text-amber-400' : 'text-slate-200'
                            }
                          >
                            {v.cvssScore.toFixed(1)}
                          </span>
                        ) : (
                          <span className="text-slate-500 font-normal italic">None</span>
                        )}
                      </td>

                      {/* 4. Description */}
                      <td className="py-3 px-3 max-w-xs">
                        <div className="text-slate-300 text-[11px] line-clamp-2 leading-relaxed">
                          {v.description || 'No description available.'}
                        </div>
                      </td>

                      {/* 5. Published */}
                      <td className="py-3 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                        {v.publishedDate ? new Date(v.publishedDate).toLocaleDateString() : 'N/A'}
                      </td>

                      {/* 6. Modified */}
                      <td className="py-3 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                        {v.modifiedDate ? new Date(v.modifiedDate).toLocaleDateString() : 'N/A'}
                      </td>

                      {/* 7. CWE */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        {v.cwe && v.cwe.length > 0 ? (
                          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                            {v.cwe[0]}
                          </span>
                        ) : (
                          <span className="text-slate-500 text-[10px] italic">None</span>
                        )}
                      </td>

                      {/* 8. Source */}
                      <td className="py-3 px-3 text-right whitespace-nowrap">
                        {v.isRealData ? (
                          <span className="inline-flex items-center gap-1 font-bold text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/60">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            Source = NVD
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 font-bold text-[10px] px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-700/60">
                            <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                            Source = Mock/Demo
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Vulnerability Detail Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Header */}
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-cyan-300 font-mono">{selectedVuln.id}</h3>
                  <DataSourceBadge origin={selectedVuln.dataSource} isRealData={selectedVuln.isRealData} size="sm" />
                  {selectedVuln.isKnownExploited && (
                    <span className="inline-flex items-center gap-1 font-bold text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700">
                      <Flame className="w-3 h-3 text-rose-400" /> CISA KEV
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-300 font-medium mt-0.5">{selectedVuln.title}</p>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="text-slate-400 hover:text-white px-2 py-1 text-sm rounded bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-300">
              {/* Description */}
              <div>
                <span className="font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  NVD Vulnerability Description:
                </span>
                <p className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 leading-relaxed font-sans">
                  {selectedVuln.description}
                </p>
              </div>

              {/* CVSS & Vector */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 uppercase font-semibold text-[10px] block">CVSS v3.1 Base Score</span>
                  <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
                    {selectedVuln.cvssScore.toFixed(1)} <span className="text-xs font-normal text-slate-400">({selectedVuln.severity})</span>
                  </div>
                  {selectedVuln.cvssVector && (
                    <span className="font-mono text-[10px] text-slate-400 block mt-1 break-all">
                      {selectedVuln.cvssVector}
                    </span>
                  )}
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 uppercase font-semibold text-[10px] block">Common Weakness (CWE)</span>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {selectedVuln.cwe && selectedVuln.cwe.length > 0 ? (
                      selectedVuln.cwe.map((c) => (
                        <span key={c} className="font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 text-[11px]">
                          {c}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500 italic">No CWE specified</span>
                    )}
                  </div>
                </div>
              </div>

              {/* CISA KEV Enrichment Details if active */}
              {selectedVuln.isKnownExploited && (
                <div className="p-4 rounded-lg bg-rose-950/30 border border-rose-800/60 space-y-2">
                  <div className="flex items-center gap-2 font-bold text-rose-300">
                    <Flame className="w-4 h-4 text-rose-400" />
                    <span>CISA Known Exploited Vulnerabilities Catalog Data</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                    <div>
                      <span className="text-slate-400">Vendor / Project:</span>{' '}
                      <span className="font-semibold text-white">{selectedVuln.kevVendorProject || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Product:</span>{' '}
                      <span className="font-semibold text-white">{selectedVuln.kevProduct || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Date Added to Catalog:</span>{' '}
                      <span className="font-mono text-cyan-300">{selectedVuln.kevDateAdded || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Federal Remediation Due Date:</span>{' '}
                      <span className="font-mono text-rose-400 font-bold">{selectedVuln.kevDueDate || 'N/A'}</span>
                    </div>
                  </div>
                  {selectedVuln.kevRequiredAction && (
                    <div className="mt-2 p-2 rounded bg-slate-900 border border-rose-900/60 text-rose-200 text-xs">
                      <strong>Required Action:</strong> {selectedVuln.kevRequiredAction}
                    </div>
                  )}
                </div>
              )}

              {/* Affected Products */}
              <div>
                <span className="font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  Affected Products &amp; CPE Criteria:
                </span>
                <div className="flex flex-wrap gap-1.5 p-3 rounded-lg bg-slate-950 border border-slate-800">
                  {selectedVuln.affectedProducts.map((p, idx) => (
                    <span key={idx} className="px-2 py-1 rounded bg-slate-800 text-slate-200 text-[11px]">
                      {p}
                    </span>
                  ))}
                </div>
              </div>

              {/* References */}
              <div>
                <span className="font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  Authoritative References:
                </span>
                <div className="space-y-1">
                  {selectedVuln.references.map((url, idx) => (
                    <a
                      key={idx}
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 truncate font-mono text-[11px]"
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{url}</span>
                    </a>
                  ))}
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-3 border-t border-slate-800 bg-slate-950 flex justify-end">
              <button
                onClick={() => setSelectedVuln(null)}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Risk Breakdown Modal */}
      <RiskBreakdownModal breakdown={selectedBreakdown} onClose={() => setSelectedBreakdown(null)} />
    </div>
  );
};
