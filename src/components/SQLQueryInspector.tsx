import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { Database, Play, CheckCircle2, AlertCircle, Copy } from 'lucide-react';

const PRESET_QUERIES = [
  {
    name: 'Real Vulnerabilities with CISA KEV Exploited Status',
    sql: 'SELECT id, cvss_score, severity, is_known_exploited, kev_vendor, data_source FROM vulnerabilities ORDER BY cvss_score DESC LIMIT 6;',
  },
  {
    name: 'Verified Real Database Record Counts by Source',
    sql: 'SELECT source_name, record_count, origin_category, status, last_updated FROM data_source_metrics;',
  },
  {
    name: 'Enterprise Assets & Computed Composite Risk',
    sql: 'SELECT id, name, criticality, exposure, calculated_risk_score, vulnerability_count FROM assets ORDER BY calculated_risk_score DESC;',
  },
  {
    name: 'Historical Security Events vs Synthetic Events Count',
    sql: 'SELECT data_source, COUNT(*) as count, is_real_data FROM security_events GROUP BY data_source;',
  },
  {
    name: 'Recent Critical Incident Events',
    sql: 'SELECT id, timestamp, source_ip, destination_ip, attack_category, severity, data_source FROM security_events WHERE severity = "CRITICAL" ORDER BY timestamp DESC LIMIT 6;',
  },
];

export const SQLQueryInspector: React.FC = () => {
  const { executeRawSql } = useCrisp();
  const [query, setQuery] = useState(PRESET_QUERIES[0].sql);
  const [result, setResult] = useState<{ columns: string[]; rows: (string | number | null)[][] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleRun = () => {
    setError(null);
    try {
      const res = executeRawSql(query);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'SQL execution error');
      setResult(null);
    }
  };

  const handlePreset = (sql: string) => {
    setQuery(sql);
    setError(null);
    try {
      const res = executeRawSql(sql);
      setResult(res);
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Run initial query on mount
  React.useEffect(() => {
    handleRun();
  }, []);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">Direct SQLite Database Inspector</h3>
            <p className="text-xs text-slate-400">
              Query local embedded SQLite (WASM engine) to inspect real tables, schemas, and records.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 text-emerald-400 font-mono">
            <CheckCircle2 className="w-3.5 h-3.5" /> SQLite Engine Active
          </span>
        </div>
      </div>

      {/* Preset Query Buttons */}
      <div>
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
          Academic Defense Query Presets:
        </span>
        <div className="flex flex-wrap gap-2">
          {PRESET_QUERIES.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handlePreset(p.sql)}
              className="text-xs px-2.5 py-1 rounded border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors text-left"
            >
              {p.name}
            </button>
          ))}
        </div>
      </div>

      {/* Query Editor */}
      <div className="relative">
        <textarea
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          rows={3}
          className="w-full font-mono text-xs bg-slate-950 border border-slate-700/80 rounded-lg p-3 text-cyan-300 focus:outline-none focus:border-cyan-500 resize-y leading-relaxed"
          placeholder="Enter SQL query, e.g. SELECT * FROM vulnerabilities..."
        />
        <div className="absolute right-3 bottom-3 flex gap-2">
          <button
            onClick={handleRun}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-md transition-colors"
          >
            <Play className="w-3.5 h-3.5 fill-current" /> Execute SQL
          </button>
        </div>
      </div>

      {/* Error display */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Result Table */}
      {result && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Result Rows: {result.rows.length}</span>
            <button
              onClick={() => {
                navigator.clipboard.writeText(JSON.stringify(result, null, 2));
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200"
            >
              <Copy className="w-3 h-3" /> {copied ? 'Copied JSON' : 'Copy Result JSON'}
            </button>
          </div>
          <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-72">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-800/80 text-slate-300 uppercase tracking-wider sticky top-0 border-b border-slate-700">
                <tr>
                  {result.columns.map((col, idx) => (
                    <th key={idx} className="py-2 px-3 whitespace-nowrap">{col}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {result.rows.length === 0 ? (
                  <tr>
                    <td colSpan={result.columns.length} className="py-4 text-center text-slate-500">
                      Query returned 0 rows.
                    </td>
                  </tr>
                ) : (
                  result.rows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-slate-800/40">
                      {row.map((val, cIdx) => (
                        <td key={cIdx} className="py-1.5 px-3 whitespace-nowrap text-slate-300">
                          {val === null ? (
                            <span className="text-slate-500 italic">NULL</span>
                          ) : typeof val === 'number' ? (
                            <span className="text-amber-300">{val}</span>
                          ) : (
                            String(val)
                          )}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
