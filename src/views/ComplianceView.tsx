import React from 'react';
import { useCrisp } from '../context/CrispContext';
import { DataSourceBadge } from '../components/DataSourceBadge';
import {
  Award,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight,
} from 'lucide-react';

export const ComplianceView: React.FC = () => {
  const { nistControls, complianceSummary, vulnerabilities } = useCrisp();

  const functionColors: Record<string, { bar: string; text: string; bg: string }> = {
    govern: { bar: 'bg-indigo-500', text: 'text-indigo-400', bg: 'bg-indigo-950/40 border-indigo-800/40' },
    identify: { bar: 'bg-cyan-500', text: 'text-cyan-400', bg: 'bg-cyan-950/40 border-cyan-800/40' },
    protect: { bar: 'bg-emerald-500', text: 'text-emerald-400', bg: 'bg-emerald-950/40 border-emerald-800/40' },
    detect: { bar: 'bg-amber-500', text: 'text-amber-400', bg: 'bg-amber-950/40 border-amber-800/40' },
    respond: { bar: 'bg-rose-500', text: 'text-rose-400', bg: 'bg-rose-950/40 border-rose-800/40' },
    recover: { bar: 'bg-purple-500', text: 'text-purple-400', bg: 'bg-purple-950/40 border-purple-800/40' },
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-xl font-bold text-white tracking-tight">
              NIST Cybersecurity Framework (CSF 2.0) Compliance
            </h2>
            <DataSourceBadge origin="CRISP_DERIVED" size="sm" />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Dynamic posture scoring correlated directly with real-time NVD vulnerability discovery and CISA KEV deadlines.
          </p>
        </div>

        {complianceSummary && (
          <div className="flex items-baseline gap-2 bg-slate-950 px-4 py-2 rounded-lg border border-slate-800">
            <span className="text-xs text-slate-400">Overall Score:</span>
            <span className="text-2xl font-mono font-extrabold text-cyan-400">
              {complianceSummary.overallCompliancePct}%
            </span>
          </div>
        )}
      </div>

      {/* CISA KEV Remediation Notice if Overdue */}
      {complianceSummary && complianceSummary.kevOverdueCount > 0 && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs text-rose-200 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-bold text-sm text-rose-300">
              CISA Binding Operational Directive Warning: {complianceSummary.kevOverdueCount} Overdue Remediation Deadlines
            </div>
            <p className="text-rose-200/80 leading-relaxed">
              Federal BOD 22-01 mandates patching known exploited vulnerabilities by their published due dates. Compliance Engine automatically degraded <strong>PR.PS-01 (Platform Security)</strong> to Non-Compliant status.
            </p>
          </div>
        </div>
      )}

      {/* 6 Core Functions Breakdown Cards */}
      {complianceSummary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {Object.entries(complianceSummary.functionScores).map(([func, score]) => {
            const style = functionColors[func] || functionColors.identify;
            return (
              <div key={func} className={`p-3.5 rounded-xl border ${style.bg} space-y-2`}>
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold uppercase tracking-wider text-slate-300">{func}</span>
                  <span className={`font-mono font-extrabold text-sm ${style.text}`}>{score}%</span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                  <div className={`h-full ${style.bar}`} style={{ width: `${score}%` }}></div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Controls Evaluation Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Award className="w-4 h-4 text-cyan-400" />
            <span>NIST CSF 2.0 Control Implementations &amp; Audit Logs</span>
          </h3>
          <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1 text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" /> Compliant
            </span>
            <span className="flex items-center gap-1 text-amber-400">
              <Clock className="w-3.5 h-3.5" /> Partial
            </span>
            <span className="flex items-center gap-1 text-rose-400">
              <XCircle className="w-3.5 h-3.5" /> Non-Compliant
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-semibold uppercase border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Control ID &amp; Function</th>
                <th className="py-3 px-4">Category &amp; Subcategory</th>
                <th className="py-3 px-4">Dynamic Findings</th>
                <th className="py-3 px-4">Required Remediation</th>
                <th className="py-3 px-4 text-center">Score</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {nistControls.map((ctrl) => {
                const isCompliant = ctrl.status === 'COMPLIANT';
                const isPartial = ctrl.status === 'PARTIAL';

                return (
                  <tr key={ctrl.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4">
                      <span className="font-mono font-bold text-cyan-300 block">{ctrl.id}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded font-semibold uppercase bg-slate-800 text-slate-400">
                        {ctrl.function}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-200">{ctrl.category}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5 max-w-xs">{ctrl.subcategory}</div>
                    </td>

                    <td className="py-3 px-4 max-w-sm">
                      <div className="text-slate-300 leading-relaxed">{ctrl.findings}</div>
                      <div className="text-[10px] text-slate-500 font-mono mt-1">Ref: {ctrl.evidence}</div>
                    </td>

                    <td className="py-3 px-4 max-w-xs">
                      {ctrl.requiredRemediation ? (
                        <div className="text-rose-300 font-medium text-[11px] bg-rose-950/40 p-2 rounded border border-rose-900/50">
                          {ctrl.requiredRemediation}
                        </div>
                      ) : (
                        <span className="text-slate-500 italic">No remediation required</span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-center font-mono font-bold text-sm">
                      <span className={isCompliant ? 'text-emerald-400' : isPartial ? 'text-amber-400' : 'text-rose-400'}>
                        {ctrl.score}%
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <span
                        className={`inline-block font-semibold uppercase text-[10px] px-2 py-0.5 rounded ${
                          isCompliant
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : isPartial
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-rose-950 text-rose-300 border border-rose-800'
                        }`}
                      >
                        {ctrl.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
