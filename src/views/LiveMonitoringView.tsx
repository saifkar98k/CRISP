import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Radio,
  Play,
  Square,
  AlertTriangle,
  Zap,
  ShieldAlert,
  Activity,
  Gauge,
  Clock,
  Server,
  Terminal,
  RefreshCw,
  Flame,
  CheckCircle,
  HelpCircle,
  Eye,
  Sliders,
  Sparkles,
} from 'lucide-react';

interface LiveStats {
  events_per_minute: number;
  events_last_5_minutes: number;
  total_events: number;
  current_risk: {
    score: number;
    level: string;
  };
  critical_incidents: {
    count: number;
    recent_critical: any[];
  };
  recent_events: any[];
  active_alert: {
    title: string;
    finding_id?: string;
    asset: string;
    risk_score: number;
    risk_level: string;
    attack_category?: string;
    cve_id?: string;
    reason: string;
    timestamp: string;
    simulation_label: string;
  } | null;
  simulation_status: {
    is_running: boolean;
    interval_seconds: number;
  };
  simulation_mode: boolean;
  disclaimer: string;
}

export const LiveMonitoringView: React.FC = () => {
  const [stats, setStats] = useState<LiveStats | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [speed, setSpeed] = useState<number>(3.0);
  const [lastActionMessage, setLastActionMessage] = useState<string | null>(null);
  const [dismissedAlertId, setDismissedAlertId] = useState<string | null>(null);
  const pollingRef = useRef<NodeJS.Timeout | null>(null);

  const fetchLiveStats = useCallback(async () => {
    try {
      const res = await fetch('/api/simulator/live-stats');
      if (res.ok) {
        const data: LiveStats = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.error('Failed to fetch live monitoring stats', e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Poll carefully every 3 seconds to avoid uncontrolled database/API loops
  useEffect(() => {
    fetchLiveStats();
    pollingRef.current = setInterval(fetchLiveStats, 3000);

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, [fetchLiveStats]);

  const handleStartSimulation = async () => {
    setIsSubmitting(true);
    try {
      const res = await fetch('/api/simulator/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ speedSeconds: speed }),
      });
      if (res.ok) {
        setLastActionMessage(`Simulation started: generating ~${Math.round(60 / speed)} events/min`);
        await fetchLiveStats();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStopSimulation = async () => {
    setIsSubmitting(true);
    try {
      const res = await fetch('/api/simulator/stop', { method: 'POST' });
      if (res.ok) {
        setLastActionMessage('Simulation stopped');
        await fetchLiveStats();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleGenerateEvent = async (type: string, label: string) => {
    setIsSubmitting(true);
    try {
      const res = await fetch('/api/simulator/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type }),
      });
      if (res.ok) {
        const result = await res.json();
        setLastActionMessage(`Generated ${label}: Risk Score ${result.risk_score}/100 (${result.risk_level})`);
        await fetchLiveStats();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsSubmitting(false);
    }
  };

  const isSimulating = stats?.simulation_status?.is_running ?? false;
  const currentRiskScore = stats?.current_risk?.score ?? 0;
  const currentRiskLevel = stats?.current_risk?.level ?? 'LOW';
  const activeAlert = stats?.active_alert;
  const showAlert = activeAlert && activeAlert.finding_id !== dismissedAlertId;

  return (
    <div className="space-y-6">
      {/* Simulation Mode Mandatory Disclaimer Banner */}
      <div className="rounded-xl border border-amber-500/40 bg-gradient-to-r from-amber-950/70 via-slate-900 to-amber-950/40 p-4 shadow-lg shadow-amber-950/20">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/20 border border-amber-500/40 flex items-center justify-center shrink-0">
              <Radio className={`w-5 h-5 text-amber-400 ${isSimulating ? 'animate-pulse' : ''}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[11px] font-black uppercase tracking-wider bg-amber-500 text-slate-950">
                  SIMULATION MODE
                </span>
                <span className="text-xs text-amber-200/80 font-medium">
                  Controlled Demonstration & Validation Environment
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                All telemetry produced on this page is synthetic and generated inside an isolated test harness.
                Simulated events are strictly separated from production infrastructure and never represent actual attacks.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold border ${
              isSimulating
                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50 animate-pulse'
                : 'bg-slate-900 text-slate-400 border-slate-700'
            }`}>
              <span className={`w-2 h-2 rounded-full ${isSimulating ? 'bg-emerald-400' : 'bg-slate-500'}`} />
              {isSimulating ? 'RUNNING' : 'STANDBY'}
            </div>
          </div>
        </div>
      </div>

      {/* Prominent Critical Security Alert Banner */}
      {showAlert && (
        <div className="rounded-xl border-2 border-rose-500 bg-gradient-to-r from-rose-950 via-slate-950 to-rose-950/90 p-5 shadow-2xl shadow-rose-900/40 animate-in fade-in slide-in-from-top-4 duration-300">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-start gap-3.5">
              <div className="w-12 h-12 rounded-xl bg-rose-600/30 border-2 border-rose-500 flex items-center justify-center shrink-0 animate-bounce">
                <Flame className="w-6 h-6 text-rose-400" />
              </div>
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-black uppercase tracking-wider bg-rose-600 text-white">
                    {activeAlert.title}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700">
                    SIMULATION MODE
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    {activeAlert.timestamp}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-1 pt-1 text-xs">
                  <div>
                    <span className="text-slate-400">Target Asset: </span>
                    <strong className="text-white font-mono">{activeAlert.asset}</strong>
                  </div>
                  <div>
                    <span className="text-slate-400">Composite Risk: </span>
                    <strong className="text-rose-300 font-bold">{activeAlert.risk_score} / 100 ({activeAlert.risk_level})</strong>
                  </div>
                  {activeAlert.cve_id && (
                    <div>
                      <span className="text-slate-400">Exploited CVE: </span>
                      <strong className="text-amber-300 font-mono">{activeAlert.cve_id}</strong>
                    </div>
                  )}
                </div>
                <p className="text-xs text-rose-200/90 pt-1 font-medium">
                  <strong>Trigger Reason:</strong> {activeAlert.reason}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 self-end md:self-center shrink-0">
              <button
                onClick={() => setDismissedAlertId(activeAlert.finding_id || 'active')}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 text-xs font-semibold transition-colors"
              >
                Acknowledge Alert
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Demo Controls Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 space-y-3">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Controlled Simulation & Injection Controls
            </h3>
          </div>
          {lastActionMessage && (
            <div className="text-xs text-cyan-300 font-mono bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-1 rounded">
              {lastActionMessage}
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2.5 pt-1">
          {/* Main Loop Controls */}
          {isSimulating ? (
            <button
              onClick={handleStopSimulation}
              disabled={isSubmitting}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition-colors shadow-lg shadow-rose-900/30 disabled:opacity-50"
            >
              <Square className="w-4 h-4 fill-white" />
              <span>Stop Simulation</span>
            </button>
          ) : (
            <button
              onClick={handleStartSimulation}
              disabled={isSubmitting}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors shadow-lg shadow-emerald-900/30 disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>Start Simulation</span>
            </button>
          )}

          {/* Speed Selector */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-300">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Rate:</span>
            <select
              value={speed}
              onChange={(e) => setSpeed(Number(e.target.value))}
              disabled={isSimulating}
              className="bg-transparent text-white font-mono font-semibold focus:outline-none cursor-pointer"
            >
              <option value={1.0} className="bg-slate-900">1.0s (Fast: 60/min)</option>
              <option value={2.0} className="bg-slate-900">2.0s (Medium: 30/min)</option>
              <option value={3.0} className="bg-slate-900">3.0s (Default: 20/min)</option>
              <option value={5.0} className="bg-slate-900">5.0s (Relaxed: 12/min)</option>
            </select>
          </div>

          <div className="h-6 w-px bg-slate-800 hidden sm:block" />

          {/* Targeted Injections */}
          <button
            onClick={() => handleGenerateEvent('critical', 'Critical Security Event')}
            disabled={isSubmitting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-rose-950 hover:bg-rose-900 text-rose-200 border border-rose-700 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Generate Critical Event</span>
          </button>

          <button
            onClick={() => handleGenerateEvent('brute_force', 'Brute Force Attack')}
            disabled={isSubmitting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-amber-950 hover:bg-amber-900 text-amber-200 border border-amber-700 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span>Generate Brute Force</span>
          </button>

          <button
            onClick={() => handleGenerateEvent('vulnerability', 'Vulnerability Detection')}
            disabled={isSubmitting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-purple-950 hover:bg-purple-900 text-purple-200 border border-purple-700 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            <Zap className="w-3.5 h-3.5 text-purple-400" />
            <span>Generate Vulnerability Event</span>
          </button>

          <button
            onClick={() => handleGenerateEvent('web_attack', 'Web SQL Injection')}
            disabled={isSubmitting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-200 border border-cyan-700 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Web Attack</span>
          </button>

          <button
            onClick={() => handleGenerateEvent('port_scan', 'Port Scan Sweep')}
            disabled={isSubmitting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-600 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            <Radio className="w-3.5 h-3.5 text-slate-400" />
            <span>Port Scan</span>
          </button>
        </div>
      </div>

      {/* Real-Time Operational Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Events Per Minute */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Events Per Minute</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-white font-mono">
              {stats?.events_per_minute ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">epm</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full ${isSimulating ? 'bg-cyan-400 animate-ping' : 'bg-slate-500'}`} />
            <span>{isSimulating ? 'Active telemetry stream' : 'Telemetry quiescent'}</span>
          </div>
        </div>

        {/* Metric 2: Events in Last 5 Minutes */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Events (Last 5 Min)</span>
            <Clock className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-indigo-200 font-mono">
              {stats?.events_last_5_minutes ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">total: {stats?.total_events ?? 0}</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            Window: T-300s to Current UTC
          </div>
        </div>

        {/* Metric 3: Current Risk */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Current Cyber Risk</span>
            <Gauge className={`w-4 h-4 ${
              currentRiskLevel === 'CRITICAL' ? 'text-rose-400' : currentRiskLevel === 'HIGH' ? 'text-amber-400' : 'text-emerald-400'
            }`} />
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              currentRiskLevel === 'CRITICAL' ? 'text-rose-400' : currentRiskLevel === 'HIGH' ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {currentRiskScore}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${
              currentRiskLevel === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' : currentRiskLevel === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
            }`}>
              {currentRiskLevel}
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            CRISP Multi-Factor Risk Assessment
          </div>
        </div>

        {/* Metric 4: Critical Incidents */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Critical Incidents</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              (stats?.critical_incidents?.count ?? 0) > 0 ? 'text-rose-400' : 'text-slate-400'
            }`}>
              {stats?.critical_incidents?.count ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono">priority alerts</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            Active Tier-1 infrastructure breaches
          </div>
        </div>
      </div>

      {/* Live Risk Pipeline Flow Visualizer */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
          Live Operational Risk Pipeline Architecture
        </h4>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-center text-xs font-mono">
          <div className="p-2.5 rounded-lg bg-slate-950 border border-cyan-800/40 text-cyan-300">
            <div className="text-[10px] text-slate-500 uppercase">Stage 1</div>
            <strong className="block text-slate-200">Event Telemetry</strong>
            <span className="text-[10px] text-cyan-400">SIMULATION Mode</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-950 border border-blue-800/40 text-blue-300">
            <div className="text-[10px] text-slate-500 uppercase">Stage 2</div>
            <strong className="block text-slate-200">SQLite Storage</strong>
            <span className="text-[10px] text-blue-400">security_events</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-950 border border-indigo-800/40 text-indigo-300">
            <div className="text-[10px] text-slate-500 uppercase">Stage 3</div>
            <strong className="block text-slate-200">Correlation Engine</strong>
            <span className="text-[10px] text-indigo-400">Asset + KEV + NVD</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-950 border border-purple-800/40 text-purple-300">
            <div className="text-[10px] text-slate-500 uppercase">Stage 4</div>
            <strong className="block text-slate-200">Risk Engine</strong>
            <span className="text-[10px] text-purple-400">Multi-Factor 0-100</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-950 border border-rose-800/40 text-rose-300 col-span-2 md:col-span-1">
            <div className="text-[10px] text-slate-500 uppercase">Stage 5</div>
            <strong className="block text-slate-200">Live Dashboard</strong>
            <span className="text-[10px] text-rose-400">Prominent Alerts</span>
          </div>
        </div>
      </div>

      {/* Recent Telemetry Stream Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Recent Security Events Telemetry
            </h3>
            <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
              Live updates every 3s
            </span>
          </div>
          <button
            onClick={fetchLiveStats}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Now</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Attack Category</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Target Dest IP</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">CVE Ref</th>
                <th className="py-2.5 px-3">Mode / Origin</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {stats?.recent_events && stats.recent_events.length > 0 ? (
                stats.recent_events.map((evt) => {
                  const isSim = evt.dataset_source === 'SIMULATED_DEMO' || evt.event_id?.startsWith('SIM-');
                  const isCrit = evt.severity === 'CRITICAL';
                  const isHigh = evt.severity === 'HIGH';

                  return (
                    <tr
                      key={evt.event_id}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        isCrit ? 'bg-rose-950/15' : isHigh ? 'bg-amber-950/10' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {evt.timestamp}
                      </td>
                      <td className="py-2.5 px-3 font-semibold text-slate-200 whitespace-nowrap">
                        {evt.event_id}
                      </td>
                      <td className="py-2.5 px-3 text-slate-100 font-sans font-medium">
                        {evt.attack_category}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-300">
                        {evt.source_ip || 'N/A'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {evt.destination_ip || 'N/A'}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isCrit
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : isHigh
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300'
                        }`}>
                          {evt.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-purple-300">
                        {evt.cve_id || <span className="text-slate-600">—</span>}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {isSim ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            SIMULATION MODE
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">
                            HISTORICAL
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    No security events in database. Click &quot;Start Simulation&quot; or generate an event above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
