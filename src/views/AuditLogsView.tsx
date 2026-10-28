import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  RefreshCw,
  Clock,
  User,
  Activity,
  FileCode,
  Eye,
  X,
} from 'lucide-react';

interface AuditLog {
  audit_id: string;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  tenant_id: string;
  action: string;
  target_type: string;
  target_id: string | null;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED';
  ip_address: string;
  details: Record<string, any>;
}

interface AuditStats {
  total_audit_events: number;
  top_actions: Record<string, number>;
  results_breakdown: Record<string, number>;
  immutability_enforced: boolean;
}

export const AuditLogsView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [actionFilter, setActionFilter] = useState('ALL');
  const [resultFilter, setResultFilter] = useState('ALL');
  const [searchActor, setSearchActor] = useState('');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const token = localStorage.getItem('crisp_token') || '';
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const params = new URLSearchParams();
      if (actionFilter !== 'ALL') params.append('action', actionFilter);
      if (resultFilter !== 'ALL') params.append('result', resultFilter);
      if (searchActor.trim()) params.append('actor_id', searchActor.trim());
      params.append('limit', '50');

      const [logsRes, statsRes] = await Promise.all([
        fetch(`/api/audit/logs?${params.toString()}`, { headers }),
        fetch('/api/audit/stats', { headers }),
      ]);

      if (logsRes.ok) {
        const data = await logsRes.json();
        if (Array.isArray(data)) setLogs(data);
      }
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [actionFilter, resultFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchLogs();
  };

  const ACTION_OPTIONS = [
    { value: 'ALL', label: 'All Actions' },
    { value: 'AUTH_LOGIN', label: 'Auth Login' },
    { value: 'AUTH_LOGOUT', label: 'Auth Logout' },
    { value: 'INVESTIGATION_START', label: 'Investigation Start' },
    { value: 'DATA_SOURCE_SYNC', label: 'Data Source Sync' },
    { value: 'DATA_SOURCE_INGEST', label: 'Telemetry Ingest' },
    { value: 'REMEDIATION_STATUS_CHANGE', label: 'Remediation Status' },
    { value: 'USER_CREATED', label: 'User Created' },
    { value: 'ACCESS_DENIED', label: 'Access Denied' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner / Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-semibold">Total Audited Events</span>
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {stats?.total_audit_events || logs.length}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span>Append-only SQLite Store</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-semibold">Tamper-Evident Security</span>
            <Lock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1.5 mt-1">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>TRIGGER IMMUTABLE</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-2">
            UPDATE &amp; DELETE blocked at database engine level
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-semibold">Access Denials</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {stats?.results_breakdown?.['DENIED'] || 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Unauthorized role or permission blocks
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-semibold">Tenant Governance</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-sm font-bold font-mono text-slate-200 mt-1">
            DEFAULT_TENANT
          </div>
          <div className="text-[11px] text-slate-500 mt-2">
            Multi-tenant data isolation active
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 flex-1 min-w-[240px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search actor email or identifier..."
              value={searchActor}
              onChange={(e) => setSearchActor(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-medium transition-colors"
          >
            Search
          </button>
        </form>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span>Action:</span>
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-md px-2 py-1 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            >
              {ACTION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Result:</span>
            <select
              value={resultFilter}
              onChange={(e) => setResultFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-md px-2 py-1 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Results</option>
              <option value="SUCCESS">Success</option>
              <option value="FAILURE">Failure</option>
              <option value="DENIED">Denied</option>
            </select>
          </div>

          <button
            onClick={fetchLogs}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900/60 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Audit ID</th>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Role</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                    {isLoading ? 'Loading immutable audit trail...' : 'No audit records match the selected filters.'}
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const isSuccess = log.result === 'SUCCESS';
                  const isDenied = log.result === 'DENIED';

                  return (
                    <tr key={log.audit_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono text-[11px] font-semibold text-slate-300">
                        {log.audit_id}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                        {log.timestamp.replace('T', ' ').substring(0, 19)}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-200">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3 h-3 text-cyan-400 shrink-0" />
                          <span className="truncate max-w-[140px]">{log.actor_id}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                          {log.actor_role}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-cyan-300 font-medium">
                        {log.action}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        <span className="text-slate-300">{log.target_type}</span>
                        {log.target_id && (
                          <span className="text-[10px] text-slate-500 block truncate max-w-[120px]">
                            {log.target_id}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold font-mono ${
                            isSuccess
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : isDenied
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {isSuccess ? (
                            <CheckCircle2 className="w-3 h-3" />
                          ) : (
                            <XCircle className="w-3 h-3" />
                          )}
                          <span>{log.result}</span>
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSelectedLog(log)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5 inline mr-1" />
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-white text-sm">
                  Audit Record [{selectedLog.audit_id}]
                </h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-slate-400 block font-medium">Timestamp:</span>
                <span className="font-mono text-slate-200">{selectedLog.timestamp}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-medium">Actor:</span>
                <span className="font-mono text-slate-200">
                  {selectedLog.actor_id} ({selectedLog.actor_role})
                </span>
              </div>
              <div>
                <span className="text-slate-400 block font-medium">Action:</span>
                <span className="font-mono text-cyan-300 font-bold">{selectedLog.action}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-medium">Result:</span>
                <span className="font-mono font-bold text-emerald-400">{selectedLog.result}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-medium">Target Type &amp; ID:</span>
                <span className="font-mono text-slate-300">
                  {selectedLog.target_type}: {selectedLog.target_id || 'N/A'}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block font-medium">Client IP:</span>
                <span className="font-mono text-slate-300">{selectedLog.ip_address}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-400 block text-xs font-medium mb-1">
                Sanitized Payload &amp; Context:
              </span>
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 max-h-48 overflow-y-auto">
                {JSON.stringify(selectedLog.details, null, 2)}
              </pre>
            </div>

            <div className="pt-2 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white font-semibold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
