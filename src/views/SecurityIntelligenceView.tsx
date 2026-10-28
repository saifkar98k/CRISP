import React from 'react';
import { useCrisp } from '../context/CrispContext';
import { VulnerabilitiesView } from './VulnerabilitiesView';
import { CorrelatedFindingsView } from './CorrelatedFindingsView';
import { RiskMatrixView } from './RiskMatrixView';
import { ComplianceView } from './ComplianceView';
import { RemediationQueueView } from './RemediationQueueView';
import { RiskBreakdownModal } from '../components/RiskBreakdownModal';
import { RiskEngine } from '../engines/riskEngine';
import { Asset, RiskScoreBreakdown } from '../types/schemas';
import {
  ShieldAlert,
  Flame,
  Server,
  GitMerge,
  Calculator,
  Award,
  Wrench,
  Search,
  ExternalLink,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';

export const SecurityIntelligenceView: React.FC = () => {
  const {
    subTab,
    setSubTab,
    vulnerabilities,
    assets,
    securityEvents,
    setActiveTab,
  } = useCrisp();

  const [selectedBreakdown, setSelectedBreakdown] = React.useState<RiskScoreBreakdown | null>(null);
  const [assetSearch, setAssetSearch] = React.useState('');
  const [assetTierFilter, setAssetTierFilter] = React.useState('ALL');

  // Sub-tabs configuration
  const SUB_TABS = [
    { id: 'vulnerabilities', label: 'Vulnerabilities & CVEs', icon: ShieldAlert, badge: `${vulnerabilities.length}` },
    { id: 'cisa_kev', label: 'CISA KEV Catalog', icon: Flame, badge: `${vulnerabilities.filter(v => v.isKnownExploited).length}` },
    { id: 'assets', label: 'Enterprise Assets', icon: Server, badge: `${assets.length}` },
    { id: 'findings', label: 'Correlated Findings', icon: GitMerge },
    { id: 'risk_matrix', label: 'Cyber Risk Matrix', icon: Calculator },
    { id: 'compliance', label: 'NIST CSF 2.0', icon: Award },
    { id: 'remediation', label: 'Remediation Queue', icon: Wrench },
  ];

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

  // Filtered Assets
  const filteredAssets = assets.filter((a) => {
    if (assetTierFilter !== 'ALL' && a.criticality !== assetTierFilter) return false;
    if (assetSearch.trim()) {
      const q = assetSearch.toLowerCase();
      return (
        a.name.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q) ||
        a.ipAddress.toLowerCase().includes(q) ||
        a.owner.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // CISA KEV Vulnerabilities
  const kevVulns = vulnerabilities.filter((v) => v.isKnownExploited);

  return (
    <div className="space-y-6">
      {/* Sub-Navigation Bar */}
      <div className="border-b border-slate-800 bg-slate-900/60 p-1.5 rounded-xl flex flex-wrap items-center gap-1">
        {SUB_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = subTab === tab.id;

          return (
            <button
              key={tab.id}
              onClick={() => setSubTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80 border border-transparent'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                  isActive
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80'
                    : 'bg-slate-950 text-slate-400 border border-slate-800'
                }`}>
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Vulnerabilities & CVEs */}
      {subTab === 'vulnerabilities' && <VulnerabilitiesView />}

      {/* Tab 2: CISA KEV Catalog */}
      {subTab === 'cisa_kev' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Flame className="w-5 h-5 text-rose-400" />
                <h3 className="text-lg font-bold text-white tracking-tight">
                  CISA Known Exploited Vulnerabilities (KEV) Catalog
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                  {kevVulns.length} ACTIVELY EXPLOITED
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Authoritative register of CVEs confirmed to be weaponized and actively exploited in real-world cyber campaigns (Binding Operational Directive 22-01).
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {kevVulns.map((v) => (
              <div
                key={v.id}
                className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-white text-sm">{v.id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 font-mono">
                      KEV CONFIRMED
                    </span>
                  </div>
                  <span className="font-mono font-bold text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                    CVSS {v.cvssScore}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{v.description}</p>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1.5">
                  <div className="flex justify-between text-slate-400">
                    <span>Vendor / Product:</span>
                    <span className="text-slate-200">{v.kevVendorProject || v.affectedProducts.join(', ') || 'Enterprise Component'}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>CISA Status:</span>
                    <span className="text-rose-400 font-bold">{v.isKnownExploited ? 'ACTIVELY EXPLOITED' : 'MONITORED'}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Due Date for Action:</span>
                    <span className="text-amber-300">{v.kevDueDate || 'Immediate'}</span>
                  </div>
                </div>

                <div className="pt-2 flex items-center justify-between">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${v.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                  >
                    NVD Advisory <ExternalLink className="w-3 h-3" />
                  </a>
                  <button
                    onClick={() => setActiveTab('swarm')}
                    className="px-3 py-1 rounded-md bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800 text-xs font-semibold"
                  >
                    Investigate with Swarm &rarr;
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Enterprise Assets & Criticality */}
      {subTab === 'assets' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-cyan-400" />
                <h3 className="text-lg font-bold text-white tracking-tight">
                  Enterprise Infrastructure &amp; Criticality Asset Inventory
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Tier-1 mission-critical assets, exposure postures, risk weightings, and real-time vulnerability associations.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter assets..."
                  value={assetSearch}
                  onChange={(e) => setAssetSearch(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-white text-xs font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>
              <select
                value={assetTierFilter}
                onChange={(e) => setAssetTierFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-300 text-xs focus:outline-none"
              >
                <option value="ALL">All Tiers</option>
                <option value="TIER-1">Tier-1 Mission Critical</option>
                <option value="TIER-2">Tier-2 Core Operations</option>
                <option value="TIER-3">Tier-3 Internal Peripheral</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredAssets.map((asset) => {
              const riskColor = asset.calculatedRiskScore >= 7.5
                ? 'text-rose-400 bg-rose-950/60 border-rose-800'
                : asset.calculatedRiskScore >= 5.0
                ? 'text-amber-400 bg-amber-950/60 border-amber-800'
                : 'text-emerald-400 bg-emerald-950/60 border-emerald-800';

              return (
                <div
                  key={asset.id}
                  className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-bold text-white text-sm">{asset.name}</h4>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">{asset.ipAddress}</p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${riskColor}`}>
                      Risk {asset.calculatedRiskScore.toFixed(1)}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1.5">
                    <div className="flex justify-between text-slate-400">
                      <span>Asset Type:</span>
                      <span className="text-white font-bold">{asset.type}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Criticality:</span>
                      <span className="text-cyan-400 font-bold">{asset.criticality}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Network Exposure:</span>
                      <span className="text-slate-200">{asset.exposure}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Owner / Team:</span>
                      <span className="text-slate-300">{asset.owner}</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <button
                      onClick={() => handleInspectAsset(asset)}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                    >
                      Formula Breakdown
                    </button>
                    <button
                      onClick={() => setActiveTab('swarm')}
                      className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
                    >
                      Swarm Investigation &rarr;
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 4: Correlated Findings */}
      {subTab === 'findings' && <CorrelatedFindingsView />}

      {/* Tab 5: Cyber Risk Matrix & Engine */}
      {subTab === 'risk_matrix' && <RiskMatrixView />}

      {/* Tab 6: NIST CSF 2.0 Compliance */}
      {subTab === 'compliance' && <ComplianceView />}

      {/* Tab 7: Remediation Recommendations Queue & Intelligence Engine */}
      {subTab === 'remediation' && <RemediationQueueView />}

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
