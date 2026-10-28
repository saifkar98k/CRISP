import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { DataSourcesView } from './DataSourcesView';
import { DataImporterView } from './DataImporterView';
import { AuditLogsView } from './AuditLogsView';
import { EnterpriseIntegrationsView } from './EnterpriseIntegrationsView';
import { SQLQueryInspector } from '../components/SQLQueryInspector';
import {
  Database,
  FileSpreadsheet,
  Terminal,
  Activity,
  CheckCircle2,
  RefreshCw,
  Cpu,
  Shield,
  Layers,
  Clock,
  Flame,
  Zap,
  ShieldAlert,
  Radio,
} from 'lucide-react';

export const DataAdminView: React.FC = () => {
  const {
    subTab,
    setSubTab,
    pipelineLogs,
    vulnerabilities,
    securityEvents,
    lastDataUpdate,
    refreshIntelligence,
    isSyncing,
  } = useCrisp();

  const SUB_TABS = [
    { id: 'sources', label: 'Data Sources & Sync', icon: Database },
    { id: 'integrations', label: 'Enterprise Telemetry & Queue', icon: Radio },
    { id: 'audit', label: 'Audit Logs & Governance', icon: ShieldAlert },
    { id: 'importer', label: 'CSV Importer & Mapping', icon: FileSpreadsheet },
    { id: 'sqlite', label: 'SQLite Inspector', icon: Terminal },
    { id: 'system', label: 'System Health & Diagnostics', icon: Activity },
  ];

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
            </button>
          );
        })}
      </div>

      {/* Tab 1: Data Sources & Sync */}
      {subTab === 'sources' && <DataSourcesView />}

      {/* Tab: Enterprise Telemetry & Queue */}
      {subTab === 'integrations' && <EnterpriseIntegrationsView />}

      {/* Tab: Audit Logs & Governance */}
      {subTab === 'audit' && <AuditLogsView />}

      {/* Tab 2: Dataset Importer & Mapping */}
      {subTab === 'importer' && <DataImporterView />}

      {/* Tab 3: SQLite Database Inspector */}
      {subTab === 'sqlite' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                <h3 className="text-lg font-bold text-white tracking-tight">
                  Embedded SQLite WebAssembly Database Inspector
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Execute parameterized and read-only SQL queries directly against the in-browser WASM database engine.
              </p>
            </div>
          </div>
          <SQLQueryInspector />
        </div>
      )}

      {/* Tab 4: System Health & Diagnostics */}
      {subTab === 'system' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                <h3 className="text-lg font-bold text-white tracking-tight">
                  System Health &amp; Pipeline Diagnostics
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Real-time execution telemetry, database health metrics, and pipeline audit logs.
              </p>
            </div>

            <button
              onClick={() => refreshIntelligence(true)}
              disabled={isSyncing}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
              <span>Verify Pipeline Integrity</span>
            </button>
          </div>

          {/* Diagnostics Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-slate-400 font-semibold uppercase">Platform Engine</span>
              <div className="text-xl font-bold text-white font-mono mt-1">CRISP v2.2 SOC</div>
              <div className="text-[11px] text-emerald-400 font-mono mt-1">Operational</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-slate-400 font-semibold uppercase">Database Engine</span>
              <div className="text-xl font-bold text-cyan-300 font-mono mt-1">SQLite WASM</div>
              <div className="text-[11px] text-slate-400 font-mono mt-1">In-Memory / IndexedDB</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-slate-400 font-semibold uppercase">Agent Swarm</span>
              <div className="text-xl font-bold text-indigo-300 font-mono mt-1">LangGraph 0.2</div>
              <div className="text-[11px] text-indigo-400 font-mono mt-1">7 Supervised Agents</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-slate-400 font-semibold uppercase">Telemetry Pipeline</span>
              <div className="text-xl font-bold text-amber-300 font-mono mt-1">{securityEvents.length} Events</div>
              <div className="text-[11px] text-slate-400 font-mono mt-1">{vulnerabilities.length} CVEs correlated</div>
            </div>
          </div>

          {/* Audit Logs */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                Pipeline Audit &amp; Execution Logs
              </h4>
              <span className="text-xs text-slate-400 font-mono">
                {pipelineLogs.length} events logged
              </span>
            </div>

            <div className="p-4 max-h-96 overflow-y-auto space-y-2 font-mono text-xs">
              {pipelineLogs.length > 0 ? (
                pipelineLogs.slice().reverse().map((log, index) => (
                  <div
                    key={index}
                    className="p-2.5 rounded bg-slate-950 border border-slate-800/80 flex items-start justify-between gap-4"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          log.status === 'SUCCESS' ? 'bg-emerald-400' : log.status === 'ERROR' ? 'bg-rose-400' : 'bg-cyan-400'
                        }`} />
                        <strong className="text-slate-200">{log.stage}</strong>
                        <span className="text-[10px] text-slate-500">{log.timestamp}</span>
                      </div>
                      <p className="text-slate-400 text-[11px] mt-1">{log.message}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[10px] text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60 font-mono">
                        {log.recordsProcessed} recs
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {log.durationMs}ms
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-slate-500 font-sans text-xs">
                  No execution logs recorded yet. Run a pipeline sync above.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
