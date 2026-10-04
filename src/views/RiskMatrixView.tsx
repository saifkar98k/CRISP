import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { Asset, RiskScoreBreakdown, RiskFactorContribution } from '../types/schemas';
import { RiskEngine } from '../engines/riskEngine';
import { DataSourceBadge } from '../components/DataSourceBadge';
import { RiskBreakdownModal } from '../components/RiskBreakdownModal';
import {
  Calculator,
  ShieldAlert,
  Server,
  Info,
  Sliders,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';

export const RiskMatrixView: React.FC = () => {
  const { assets, vulnerabilities, securityEvents, recalculateRisk, isSyncing } = useCrisp();
  const [selectedBreakdown, setSelectedBreakdown] = useState<RiskScoreBreakdown | null>(null);

  // Interactive Risk Simulator State
  const [simCvss, setSimCvss] = useState<number>(9.8);
  const [simKevExploited, setSimKevExploited] = useState<boolean>(true);
  const [simCriticality, setSimCriticality] = useState<Asset['criticality']>('CRITICAL');
  const [simExposure, setSimExposure] = useState<Asset['exposure']>('EXTERNAL');
  const [simEventsCount, setSimEventsCount] = useState<number>(4);

  // Calculate simulated score on the fly
  const computeSimulatedScore = () => {
    const factors: RiskFactorContribution[] = [];

    // CVSS factor
    const cvssContrib = Number((simCvss * 0.30).toFixed(2));
    factors.push({
      factor: 'CVSS Base Score',
      value: simCvss.toFixed(1),
      weight: 0.30,
      scoreContribution: cvssContrib,
      description: `CVSS score scaled by weight 0.30 (Contribution: +${cvssContrib})`,
    });

    // KEV factor
    const kevContrib = simKevExploited ? 2.50 : 0.00;
    factors.push({
      factor: 'CISA KEV Status',
      value: simKevExploited ? 'YES (Exploited)' : 'NO',
      weight: 0.25,
      scoreContribution: kevContrib,
      description: simKevExploited ? 'Confirmed active weaponization in the wild (+2.50)' : 'Unlisted in KEV',
    });

    // Criticality
    let critContrib = 0.30;
    if (simCriticality === 'CRITICAL') critContrib = 2.00;
    else if (simCriticality === 'HIGH') critContrib = 1.40;
    else if (simCriticality === 'MEDIUM') critContrib = 0.80;

    factors.push({
      factor: 'Asset Criticality',
      value: simCriticality,
      weight: 0.20,
      scoreContribution: critContrib,
      description: `Asset criticality tier (+${critContrib})`,
    });

    // Exposure
    let expContrib = 0.10;
    if (simExposure === 'EXTERNAL') expContrib = 1.50;
    else if (simExposure === 'DMZ') expContrib = 1.00;
    else if (simExposure === 'INTERNAL') expContrib = 0.50;

    factors.push({
      factor: 'Network Exposure',
      value: simExposure,
      weight: 0.15,
      scoreContribution: expContrib,
      description: `Network boundary placement (+${expContrib})`,
    });

    // Event frequency
    let freqContrib = 0.0;
    if (simEventsCount >= 5) freqContrib = 1.00;
    else if (simEventsCount >= 2) freqContrib = 0.60;
    else if (simEventsCount === 1) freqContrib = 0.30;

    factors.push({
      factor: 'Active Event Velocity',
      value: `${simEventsCount} alerts`,
      weight: 0.10,
      scoreContribution: freqContrib,
      description: `Recent attack telemetry hits (+${freqContrib})`,
    });

    const rawTotal = cvssContrib + kevContrib + critContrib + expContrib + freqContrib;
    const finalScore = Number(Math.min(10.0, Math.max(0.0, rawTotal)).toFixed(1));

    let tier: RiskScoreBreakdown['severityTier'] = 'LOW';
    if (finalScore >= 9.0) tier = 'CRITICAL';
    else if (finalScore >= 7.0) tier = 'HIGH';
    else if (finalScore >= 4.0) tier = 'MEDIUM';

    return {
      finalScore,
      tier,
      factors,
    };
  };

  const simResult = computeSimulatedScore();

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
      {/* Top Formula & Academic Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <Calculator className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-white tracking-tight">CRISP Risk Scoring Engine</h2>
                <DataSourceBadge origin="CRISP_DERIVED" size="sm" />
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Transparent multi-factor quantitative cybersecurity risk formulation.
              </p>
            </div>
          </div>

          <button
            onClick={() => recalculateRisk()}
            disabled={isSyncing}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold shadow transition-colors disabled:opacity-50"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>Recalculate All Assets</span>
          </button>
        </div>

        {/* Formula Representation */}
        <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs space-y-2">
          <div className="flex items-center gap-1.5 text-cyan-400 font-sans font-semibold">
            <Info className="w-4 h-4" /> Mathematical Formula Definition:
          </div>
          <div className="text-cyan-300 text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
            CRISP_Risk = min(10.0, F_CVSS(30%) + F_CISA_KEV(25%) + F_Criticality(20%) + F_Exposure(15%) + F_Frequency(10%))
          </div>
          <div className="text-[11px] text-slate-400 font-sans grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 pt-1 border-t border-slate-900">
            <div>• <strong className="text-slate-300">F_CVSS:</strong> Base CVSS × 0.30 (Max 3.0 pts)</div>
            <div>• <strong className="text-slate-300">F_CISA_KEV:</strong> +2.50 pts if exploited (+0.50 if overdue)</div>
            <div>• <strong className="text-slate-300">F_Criticality:</strong> Critical +2.0, High +1.4, Med +0.8, Low +0.3</div>
            <div>• <strong className="text-slate-300">F_Exposure:</strong> External +1.5, DMZ +1.0, Internal +0.5, Isolated +0.1</div>
            <div>• <strong className="text-slate-300">F_Frequency:</strong> ≥5 events +1.0, 2-4 events +0.6, 1 event +0.3</div>
            <div>• <strong className="text-slate-300">Output Range:</strong> [0.0 - 10.0] with 4 severity tiers</div>
          </div>
        </div>

        {/* Mandatory Disclaimer */}
        <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-800/40 text-amber-200/90 text-xs flex gap-2.5 items-start">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="font-semibold text-amber-300">Notice:</strong> The CRISP Composite Risk Score is an operational engineering metric designed for prioritization. It is <strong>NOT an official NIST score or CVSS standard</strong>. All weights and multipliers are fully inspectable.
          </p>
        </div>
      </div>

      {/* Interactive Risk Simulator & Asset Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Assets Table */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Evaluated Enterprise Assets ({assets.length})</span>
            </h3>
            <span className="text-xs text-slate-400">Sorted by Composite Risk</span>
          </div>

          <div className="border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-semibold uppercase border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Asset</th>
                  <th className="py-2.5 px-3">Tier &amp; Exposure</th>
                  <th className="py-2.5 px-3">CVEs</th>
                  <th className="py-2.5 px-3 text-right">CRISP Risk</th>
                  <th className="py-2.5 px-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {assets.map((a) => {
                  const isCrit = a.calculatedRiskScore >= 9.0;
                  const isHigh = a.calculatedRiskScore >= 7.0 && a.calculatedRiskScore < 9.0;

                  return (
                    <tr key={a.id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3">
                        <div className="font-bold text-slate-100">{a.name}</div>
                        <div className="text-[10px] text-slate-400 font-mono">{a.id} • {a.ipAddress}</div>
                      </td>

                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`text-[10px] font-bold px-1.5 py-0.2 rounded uppercase ${
                              a.criticality === 'CRITICAL'
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : 'bg-amber-950 text-amber-300 border border-amber-800'
                            }`}
                          >
                            {a.criticality}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-mono">
                            {a.exposure}
                          </span>
                        </div>
                      </td>

                      <td className="py-2.5 px-3 font-mono text-cyan-400 font-semibold">
                        {a.vulnerabilityCount}
                      </td>

                      <td className="py-2.5 px-3 text-right font-mono font-extrabold text-sm">
                        <span className={isCrit ? 'text-rose-400' : isHigh ? 'text-amber-400' : 'text-emerald-400'}>
                          {a.calculatedRiskScore.toFixed(1)}
                        </span>
                        <span className="text-[10px] text-slate-500 font-normal"> / 10</span>
                      </td>

                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => handleInspectAsset(a)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs border border-slate-700 transition-colors"
                        >
                          Factors
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Live Interactive Risk Simulator */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-bold text-slate-100">Live Risk Simulator</h3>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
              Interactive Testbed
            </span>
          </div>

          {/* Computed Result Box */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">
                Simulated Composite Score
              </span>
              <div className="text-3xl font-extrabold font-mono text-cyan-300 mt-1">
                {simResult.finalScore.toFixed(1)} <span className="text-xs text-slate-500 font-normal">/ 10.0</span>
              </div>
            </div>

            <div
              className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider ${
                simResult.tier === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : simResult.tier === 'HIGH'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}
            >
              {simResult.tier} TIER
            </div>
          </div>

          {/* Interactive Controls */}
          <div className="space-y-3 text-xs">
            {/* CVSS Slider */}
            <div className="space-y-1">
              <div className="flex justify-between text-slate-300">
                <span>CVSS Base Score:</span>
                <span className="font-mono font-bold text-cyan-400">{simCvss.toFixed(1)}</span>
              </div>
              <input
                type="range"
                min="0"
                max="10"
                step="0.1"
                value={simCvss}
                onChange={(e) => setSimCvss(Number(e.target.value))}
                className="w-full accent-cyan-500"
              />
            </div>

            {/* CISA KEV Exploited Toggle */}
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-300">CISA Known Exploited Status:</span>
              <button
                type="button"
                onClick={() => setSimKevExploited(!simKevExploited)}
                className={`px-2.5 py-1 rounded font-bold text-xs transition-colors ${
                  simKevExploited
                    ? 'bg-rose-950 text-rose-300 border border-rose-700'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                {simKevExploited ? 'YES (+2.5 pts)' : 'NO (0.0 pts)'}
              </button>
            </div>

            {/* Asset Criticality */}
            <div className="space-y-1">
              <label className="text-slate-300">Asset Business Criticality:</label>
              <div className="grid grid-cols-4 gap-1.5">
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Asset['criticality'][]).map((c) => (
                  <button
                    key={c}
                    onClick={() => setSimCriticality(c)}
                    className={`py-1 rounded text-[11px] font-semibold transition-colors ${
                      simCriticality === c
                        ? 'bg-slate-800 text-amber-300 border border-amber-600'
                        : 'bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>

            {/* Network Exposure */}
            <div className="space-y-1">
              <label className="text-slate-300">Network Exposure Tier:</label>
              <div className="grid grid-cols-4 gap-1.5">
                {(['EXTERNAL', 'DMZ', 'INTERNAL', 'ISOLATED'] as Asset['exposure'][]).map((exp) => (
                  <button
                    key={exp}
                    onClick={() => setSimExposure(exp)}
                    className={`py-1 rounded text-[11px] font-semibold transition-colors ${
                      simExposure === exp
                        ? 'bg-slate-800 text-cyan-300 border border-cyan-600'
                        : 'bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {exp}
                  </button>
                ))}
              </div>
            </div>

            {/* Telemetry Alert Count */}
            <div className="space-y-1">
              <div className="flex justify-between text-slate-300">
                <span>Recent Active Alerts:</span>
                <span className="font-mono font-bold text-cyan-400">{simEventsCount} alerts</span>
              </div>
              <input
                type="range"
                min="0"
                max="10"
                step="1"
                value={simEventsCount}
                onChange={(e) => setSimEventsCount(Number(e.target.value))}
                className="w-full accent-cyan-500"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Inspector Modal */}
      <RiskBreakdownModal breakdown={selectedBreakdown} onClose={() => setSelectedBreakdown(null)} />
    </div>
  );
};
