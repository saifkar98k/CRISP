import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import { RefreshCw, CheckCircle2, AlertCircle, Database, Shield, Zap } from 'lucide-react';
import { DataSourceBadge } from './DataSourceBadge';

export const NvdSyncWidget: React.FC = () => {
  const { nvdSyncStatus, lastSyncStats, syncNvd, isSyncing, vulnerabilities } = useCrisp();
  const [syncMessage, setSyncMessage] = useState<string | null>(null);

  // Fallback count from vulnerabilities state if metadata not yet populated
  const totalNvdStored = nvdSyncStatus?.total_nvd_vulnerabilities ?? vulnerabilities.filter((v) => v.dataSource === 'NVD_API').length;
  const connection = nvdSyncStatus?.connection || 'Connected';
  const lastSync = nvdSyncStatus?.last_synchronization || 'Just now';

  const handleSync = async () => {
    setSyncMessage(null);
    try {
      const stats = await syncNvd(20);
      setSyncMessage(
        `Sync Finished: Fetched ${stats.fetched} | Inserted ${stats.inserted} | Updated ${stats.updated} | Failed ${stats.failed}`
      );
    } catch (err: any) {
      setSyncMessage(`Sync failed: ${err.message || 'API error'}`);
    }
  };

  const isConnected = connection === 'Connected';

  return (
    <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-200">NVD STATUS</span>
              <DataSourceBadge origin="NVD_API" size="sm" />
            </div>
            <p className="text-[11px] text-slate-400">NIST National Vulnerability Database 2.0 Integration</p>
          </div>
        </div>

        <button
          onClick={handleSync}
          disabled={isSyncing}
          className="flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold shadow transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
          <span>{isSyncing ? 'Syncing NVD...' : 'Sync NVD'}</span>
        </button>
      </div>

      {/* Grid of stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
        {/* Connection status */}
        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
          <span className="text-slate-400 text-[10px] uppercase font-semibold font-sans block mb-1">
            Connection:
          </span>
          <div className="flex items-center gap-1.5">
            {isConnected ? (
              <span className="flex items-center gap-1 text-emerald-400 font-bold">
                <CheckCircle2 className="w-3.5 h-3.5" /> Connected
              </span>
            ) : (
              <span className="flex items-center gap-1 text-rose-400 font-bold">
                <AlertCircle className="w-3.5 h-3.5" /> Error
              </span>
            )}
          </div>
        </div>

        {/* Last synchronization */}
        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
          <span className="text-slate-400 text-[10px] uppercase font-semibold font-sans block mb-1">
            Last synchronization:
          </span>
          <div className="text-cyan-300 font-semibold truncate">
            {lastSync}
          </div>
        </div>

        {/* Total NVD vulnerabilities stored */}
        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
          <span className="text-slate-400 text-[10px] uppercase font-semibold font-sans block mb-1">
            Total NVD vulnerabilities stored:
          </span>
          <div className="text-white font-extrabold text-sm">
            {totalNvdStored.toLocaleString()} <span className="text-[10px] text-slate-500 font-normal">records in SQLite</span>
          </div>
        </div>
      </div>

      {/* Actual synchronization statistics report */}
      {(syncMessage || lastSyncStats) && (
        <div className="p-2.5 rounded-lg bg-slate-950/80 border border-cyan-800/40 text-[11px] font-mono flex items-center justify-between text-cyan-300">
          <span>
            {syncMessage ||
              `Last Sync Stats: Fetched ${lastSyncStats?.fetched} | Inserted ${lastSyncStats?.inserted} | Updated ${lastSyncStats?.updated} | Failed ${lastSyncStats?.failed}`}
          </span>
          <span className="text-[10px] text-slate-400 font-sans">Calculated from actual operation</span>
        </div>
      )}
    </div>
  );
};
