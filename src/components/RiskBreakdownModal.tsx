import React from 'react';
import { RiskScoreBreakdown } from '../types/schemas';
import { ShieldAlert, X, Info, Calculator, AlertTriangle } from 'lucide-react';
import { DataSourceBadge } from './DataSourceBadge';

interface RiskBreakdownModalProps {
  breakdown: RiskScoreBreakdown | null;
  onClose: () => void;
}

export const RiskBreakdownModal: React.FC<RiskBreakdownModalProps> = ({ breakdown, onClose }) => {
  if (!breakdown) return null;

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-950/50 border-rose-600/40';
      case 'HIGH':
        return 'text-amber-400 bg-amber-950/50 border-amber-600/40';
      case 'MEDIUM':
        return 'text-yellow-300 bg-yellow-950/50 border-yellow-600/40';
      default:
        return 'text-emerald-400 bg-emerald-950/50 border-emerald-600/40';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <Calculator className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-100">Transparent Risk Score Breakdown</h3>
                <DataSourceBadge origin="CRISP_DERIVED" size="sm" />
              </div>
              <p className="text-xs text-slate-400">Target: {breakdown.targetId} ({breakdown.targetType})</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Top Score Banner */}
          <div className="flex items-center justify-between p-4 rounded-lg bg-slate-800/80 border border-slate-700">
            <div>
              <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Calculated CRISP Risk</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-extrabold text-white">{breakdown.overallScore.toFixed(1)}</span>
                <span className="text-sm text-slate-400">/ 10.0</span>
              </div>
            </div>
            <div className={`px-3 py-1.5 rounded-md border text-xs font-bold uppercase tracking-wider ${getTierColor(breakdown.severityTier)}`}>
              {breakdown.severityTier} RISK
            </div>
          </div>

          {/* Formula Display */}
          <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 font-mono text-xs text-slate-300">
            <div className="flex items-center gap-1.5 text-slate-400 mb-1 font-sans text-xs font-medium">
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              <span>Mathematical Formula Formulation:</span>
            </div>
            <div className="text-cyan-300 overflow-x-auto whitespace-pre-wrap">{breakdown.formulaExplanation}</div>
          </div>

          {/* Factors Table */}
          <div>
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2.5">
              Contributing Factors &amp; Multipliers
            </h4>
            <div className="border border-slate-800 rounded-lg overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-800/60 text-slate-400 font-medium border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Factor</th>
                    <th className="py-2.5 px-3">Observed Input</th>
                    <th className="py-2.5 px-3 text-right">Contribution</th>
                    <th className="py-2.5 px-3">Reasoning</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-slate-200">
                  {breakdown.factors.map((f, i) => (
                    <tr key={i} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3 font-semibold text-slate-100">{f.factor}</td>
                      <td className="py-2.5 px-3 text-slate-300 font-mono">{f.value}</td>
                      <td className="py-2.5 px-3 text-right font-mono font-bold text-amber-400">
                        +{f.scoreContribution.toFixed(2)}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] leading-relaxed">
                        {f.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Disclaimer Box */}
          <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-800/40 text-amber-200/90 text-xs flex gap-2.5 items-start">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <strong className="font-semibold text-amber-300">Methodology Disclaimer:</strong> {breakdown.disclaimer}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
