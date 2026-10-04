import React from 'react';
import { DataSourceBadge } from './DataSourceBadge';

interface MetricCardProps {
  label: string;
  value: string | number;
  delta?: {
    value: string;
    isPositive?: boolean; // if positive is good or bad
    neutral?: boolean;
  };
  subtitle?: string;
  icon?: React.ElementType;
  sourceOrigin?: 'NVD_API' | 'CISA_KEV' | 'HISTORICAL_DATASET' | 'SYNTHETIC_DEMO' | 'CRISP_DERIVED';
  alert?: boolean;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  delta,
  subtitle,
  icon: Icon,
  sourceOrigin,
  alert,
}) => {
  return (
    <div
      className={`p-4 rounded-xl border transition-all ${
        alert
          ? 'bg-rose-950/20 border-rose-800/50 shadow-md shadow-rose-950/30'
          : 'bg-slate-900 border-slate-800 hover:border-slate-700 shadow-sm'
      }`}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{label}</span>
        {sourceOrigin && <DataSourceBadge origin={sourceOrigin} size="sm" />}
      </div>

      <div className="flex items-baseline justify-between mt-1">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="w-5 h-5 text-cyan-400" />}
          <span className="text-2xl font-extrabold text-white tracking-tight font-mono">{value}</span>
        </div>

        {delta && (
          <span
            className={`text-[11px] font-semibold px-1.5 py-0.5 rounded font-mono ${
              delta.neutral
                ? 'bg-slate-800 text-slate-300'
                : delta.isPositive
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : 'bg-rose-950 text-rose-400 border border-rose-800'
            }`}
          >
            {delta.value}
          </span>
        )}
      </div>

      {subtitle && <p className="text-[11px] text-slate-400 mt-2">{subtitle}</p>}
    </div>
  );
};
