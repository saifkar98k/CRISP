import React from 'react';

interface DataSourceBadgeProps {
  origin: 'NVD_API' | 'CISA_KEV' | 'HISTORICAL_DATASET' | 'SYNTHETIC_DEMO' | 'CRISP_DERIVED' | string;
  isRealData?: boolean;
  size?: 'sm' | 'md';
}

export const DataSourceBadge: React.FC<DataSourceBadgeProps> = ({
  origin,
  isRealData,
  size = 'md',
}) => {
  const sizeClasses = size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-0.5';

  if (origin === 'SYNTHETIC_DEMO' || isRealData === false) {
    return (
      <span
        className={`inline-flex items-center gap-1 font-semibold rounded border border-purple-500/40 bg-purple-950/60 text-purple-300 ${sizeClasses}`}
        title="Simulated demo event strictly for controlled academic/viva testing. Not real external telemetry."
      >
        <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse"></span>
        SYNTHETIC DEMO
      </span>
    );
  }

  if (origin === 'CISA_KEV') {
    return (
      <span
        className={`inline-flex items-center gap-1 font-semibold rounded border border-rose-500/40 bg-rose-950/60 text-rose-300 ${sizeClasses}`}
        title="Real public intelligence from the CISA Known Exploited Vulnerabilities Catalog."
      >
        <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
        REAL: CISA KEV
      </span>
    );
  }

  if (origin === 'NVD_API') {
    return (
      <span
        className={`inline-flex items-center gap-1 font-semibold rounded border border-emerald-500/40 bg-emerald-950/60 text-emerald-300 ${sizeClasses}`}
        title="Real public vulnerability record retrieved from the NIST National Vulnerability Database API 2.0."
      >
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
        REAL: NVD CVE
      </span>
    );
  }

  if (origin === 'CIC-IDS2017' || origin === 'HISTORICAL_PUBLIC_DATASET') {
    return (
      <span
        className={`inline-flex items-center gap-1 font-semibold rounded border border-cyan-500/40 bg-cyan-950/60 text-cyan-300 ${sizeClasses}`}
        title="Historical public benchmark dataset (CIC-IDS2017, UNB). Controlled research environment benchmark."
      >
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
        HISTORICAL: CIC-IDS2017
      </span>
    );
  }

  if (origin === 'HISTORICAL_DATASET') {
    return (
      <span
        className={`inline-flex items-center gap-1 font-semibold rounded border border-sky-500/40 bg-sky-950/60 text-sky-300 ${sizeClasses}`}
        title="Real public cybersecurity incident dataset imported via CSV data provider."
      >
        <span className="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
        REAL: HISTORICAL
      </span>
    );
  }

  if (origin === 'CRISP_DERIVED') {
    return (
      <span
        className={`inline-flex items-center gap-1 font-semibold rounded border border-amber-500/40 bg-amber-950/60 text-amber-300 ${sizeClasses}`}
        title="Derived multi-factor risk score calculated by CRISP. Not an official NIST standard."
      >
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
        DERIVED SCORE
      </span>
    );
  }

  return (
    <span
      className={`inline-flex items-center gap-1 font-medium rounded border border-slate-700 bg-slate-800 text-slate-300 ${sizeClasses}`}
    >
      {origin}
    </span>
  );
};
