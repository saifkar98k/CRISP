import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useCrisp } from '../context/CrispContext';
import { SecurityEvent } from '../types/schemas';
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
  Eye,
  Sliders,
  Filter,
  Search,
  Trash2,
  X,
  ExternalLink,
  Layers,
  ArrowRight,
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
  const {
    securityEvents,
    clearSyntheticEvents,
  } = useCrisp();

  const [stats, setStats] = useState<LiveStats | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [speed, setSpeed] = useState<number>(3.0);
  const [lastActionMessage, setLastActionMessage] = useState<string | null>(null);
  const [dismissedAlertId, setDismissedAlertId] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [provenanceFilter, setProvenanceFilter] = useState<'ALL' | 'REAL_HISTORICAL' | 'SYNTHETIC'>('ALL');

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

  useEffect(() => {
    fetchLiveStats();
    pollingRef.current = setInterval(fetchLiveStats, 2500);

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

  // Combine live stats events with context events for complete view
  const allEvents = useMemo(() => {
    const liveRecent = stats?.recent_events || [];
    const eventMap = new Map();
    liveRecent.forEach((e: any) => eventMap.set(e.event_id || e.id, e));
    securityEvents.forEach((e) => {
      if (!eventMap.has(e.id)) {
        eventMap.set(e.id, {
          event_id: e.id,
          timestamp: e.timestamp,
          attack_category: e.attackCategory,
          source_ip: e.sourceIp,
          destination_ip: e.destinationIp,
          source_port: e.sourcePort,
          destination_port: e.destinationPort,
          protocol: e.protocol,
          severity: e.severity,
          cve_id: e.relatedCveId,
          asset_id: e.assetId,
          description: e.description,
          dataset_source: e.isRealData ? 'CIC-IDS2017' : 'SIMULATED_DEMO',
          nist_function: e.nistFunction,
        });
      }
    });
    return Array.from(eventMap.values());
  }, [stats?.recent_events, securityEvents]);

  // Provenance counts
  const syntheticCount = allEvents.filter(
    (e: any) => e.dataset_source === 'SIMULATED_DEMO' || e.event_id?.startsWith('SIM-') || !e.isRealData
  ).length;
  const historicalCount = allEvents.filter(
    (e: any) => e.dataset_source === 'CIC-IDS2017' || e.dataset_source === 'HISTORICAL' || (e.isRealData && !e.event_id?.startsWith('REAL-API'))
  ).length;
  const realExternalCount = Math.max(0, allEvents.length - syntheticCount - historicalCount);

  // Filtered Events
  const filteredEvents = useMemo(() => {
    return allEvents.filter((evt: any) => {
      const isSim = evt.dataset_source === 'SIMULATED_DEMO' || evt.event_id?.startsWith('SIM-');

      if (provenanceFilter === 'REAL_HISTORICAL' && isSim) return false;
      if (provenanceFilter === 'SYNTHETIC' && !isSim) return false;

      if (severityFilter !== 'ALL' && evt.severity !== severityFilter) return false;
      if (categoryFilter !== 'ALL' && evt.attack_category !== categoryFilter) return false;

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesId = evt.event_id?.toLowerCase().includes(query);
        const matchesCategory = evt.attack_category?.toLowerCase().includes(query);
        const matchesSrc = evt.source_ip?.toLowerCase().includes(query);
        const matchesDest = evt.destination_ip?.toLowerCase().includes(query);
        const matchesCve = evt.cve_id?.toLowerCase().includes(query);
        if (!matchesId && !matchesCategory && !matchesSrc && !matchesDest && !matchesCve) return false;
      }

      return true;
    });
  }, [allEvents, provenanceFilter, severityFilter, categoryFilter, searchQuery]);

  // Unique categories for filter dropdown
  const uniqueCategories = useMemo(() => {
    const cats = new Set<string>();
    allEvents.forEach((e: any) => {
      if (e.attack_category) cats.add(e.attack_category);
    });
    return Array.from(cats);
  }, [allEvents]);

  return (
    <div className="space-y-6">
      {/* Top Header & Simulation Control Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 space-y-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Radio className={`w-4 h-4 text-cyan-400 ${isSimulating ? 'animate-pulse' : ''}`} />
              <h2 className="text-base font-bold text-white tracking-tight">
                Live Incident &amp; Telemetry Operations Center
              </h2>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                isSimulating
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}>
                {isSimulating ? 'SIMULATION ACTIVE' : 'QUIESCENT'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Real-time event streaming, controlled cyber attack simulation harness, and multi-vector telemetry correlation.
            </p>
          </div>

          {/* Action Message feedback */}
          {lastActionMessage && (
            <div className="text-xs text-cyan-300 font-mono bg-cyan-950/70 border border-cyan-800/80 px-3 py-1 rounded-md self-start md:self-center">
              {lastActionMessage}
            </div>
          )}
        </div>

        {/* Compact Simulation Control Strip */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800">
          <div className="flex flex-wrap items-center gap-2">
            {/* Start / Stop Toggle */}
            {isSimulating ? (
              <button
                onClick={handleStopSimulation}
                disabled={isSubmitting}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition-colors shadow-sm disabled:opacity-50"
              >
                <Square className="w-3.5 h-3.5 fill-white" />
                <span>Stop Simulation</span>
              </button>
            ) : (
              <button
                onClick={handleStartSimulation}
                disabled={isSubmitting}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors shadow-sm disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-white" />
                <span>Start Simulation</span>
              </button>
            )}

            {/* Speed Selector */}
            <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-300">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400 text-[11px]">Speed:</span>
              <select
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
                disabled={isSimulating}
                className="bg-transparent text-white font-mono font-semibold text-xs focus:outline-none cursor-pointer"
              >
                <option value={1.0} className="bg-slate-900">1.0s (60 epm)</option>
                <option value={2.0} className="bg-slate-900">2.0s (30 epm)</option>
                <option value={3.0} className="bg-slate-900">3.0s (20 epm)</option>
                <option value={5.0} className="bg-slate-900">5.0s (12 epm)</option>
              </select>
            </div>

            {/* Injections Dropdown / Buttons */}
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => handleGenerateEvent('critical', 'Critical Security Event')}
                disabled={isSubmitting}
                className="px-2.5 py-1.5 rounded-lg bg-rose-950/70 hover:bg-rose-900 text-rose-300 border border-rose-800 text-xs font-semibold transition-colors disabled:opacity-50"
                title="Inject Critical Incident into SQLite"
              >
                + Critical Event
              </button>
              <button
                onClick={() => handleGenerateEvent('web_attack', 'Web SQL Injection')}
                disabled={isSubmitting}
                className="px-2.5 py-1.5 rounded-lg bg-cyan-950/70 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold transition-colors disabled:opacity-50"
              >
                + Web Attack
              </button>
              <button
                onClick={() => handleGenerateEvent('brute_force', 'Brute Force')}
                disabled={isSubmitting}
                className="px-2.5 py-1.5 rounded-lg bg-amber-950/70 hover:bg-amber-900 text-amber-300 border border-amber-800 text-xs font-semibold transition-colors disabled:opacity-50"
              >
                + Brute Force
              </button>
            </div>
          </div>

          {/* Clear Synthetic Events */}
          <button
            onClick={() => {
              clearSyntheticEvents();
              setLastActionMessage('Synthetic demo events purged from active state');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-rose-300 border border-slate-800 text-xs transition-colors"
            title="Purge generated synthetic events"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Purge Synthetic</span>
          </button>
        </div>
      </div>

      {/* Prominent Critical Security Alert Banner */}
      {showAlert && (
        <div className="rounded-xl border-2 border-rose-500 bg-gradient-to-r from-rose-950 via-slate-950 to-rose-950/90 p-4 shadow-xl shadow-rose-900/30">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-lg bg-rose-600/30 border border-rose-500 flex items-center justify-center shrink-0">
                <Flame className="w-5 h-5 text-rose-400" />
              </div>
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-xs font-black uppercase tracking-wider bg-rose-600 text-white">
                    {activeAlert.title}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700">
                    SIMULATION MODE
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    {activeAlert.timestamp}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-4 text-xs text-slate-300 pt-0.5">
                  <span>Target: <strong className="text-white font-mono">{activeAlert.asset}</strong></span>
                  <span>Composite Risk: <strong className="text-rose-300 font-mono">{activeAlert.risk_score}/100 ({activeAlert.risk_level})</strong></span>
                  {activeAlert.cve_id && <span>CVE: <strong className="text-amber-300 font-mono">{activeAlert.cve_id}</strong></span>}
                </div>
                <p className="text-xs text-rose-200 font-medium">
                  <strong>Trigger:</strong> {activeAlert.reason}
                </p>
              </div>
            </div>
            <button
              onClick={() => setDismissedAlertId(activeAlert.finding_id || 'active')}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs font-semibold shrink-0 transition-colors"
            >
              Acknowledge
            </button>
          </div>
        </div>
      )}

      {/* Provenance & Telemetry Statistics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Events per Minute */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Stream Rate</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-white font-mono">{stats?.events_per_minute ?? 0}</span>
            <span className="text-xs text-slate-400 font-mono">epm</span>
          </div>
          <div className="text-[11px] text-slate-400 flex items-center gap-1.5 pt-1">
            <span className={`w-1.5 h-1.5 rounded-full ${isSimulating ? 'bg-cyan-400 animate-ping' : 'bg-slate-600'}`} />
            <span>{isSimulating ? 'Active pipeline ingest' : 'Generator paused'}</span>
          </div>
        </div>

        {/* Provenance: Synthetic vs Real/Historical */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Synthetic Demo</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-amber-300 font-mono">{syntheticCount}</span>
            <span className="text-xs text-slate-400 font-mono">events</span>
          </div>
          <div className="text-[11px] text-amber-400/90 pt-1 font-mono">
            Harness-generated test events
          </div>
        </div>

        {/* Provenance: Historical CIC-IDS2017 */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Historical CIC-IDS</span>
            <Server className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-indigo-300 font-mono">{historicalCount}</span>
            <span className="text-xs text-slate-400 font-mono">records</span>
          </div>
          <div className="text-[11px] text-slate-400 pt-1 font-mono">
            CIC-IDS2017 PCAP &amp; NetFlow
          </div>
        </div>

        {/* Current Risk Level */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Operational Risk</span>
            <Gauge className={`w-4 h-4 ${currentRiskLevel === 'CRITICAL' ? 'text-rose-400' : 'text-emerald-400'}`} />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-white font-mono">{currentRiskScore}</span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${
              currentRiskLevel === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
            }`}>
              {currentRiskLevel}
            </span>
          </div>
          <div className="text-[11px] text-slate-400 pt-1 font-mono">
            Dynamically updated
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          {/* Search Input */}
          <div className="relative min-w-[200px] flex-1 max-w-sm">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search event ID, IP, CVE or attack..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px]">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Category Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px]">Attack:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs focus:outline-none max-w-[160px]"
            >
              <option value="ALL">All Categories</option>
              {uniqueCategories.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>

          {/* Provenance Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px]">Source:</span>
            <select
              value={provenanceFilter}
              onChange={(e) => setProvenanceFilter(e.target.value as any)}
              className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-xs focus:outline-none"
            >
              <option value="ALL">All Sources</option>
              <option value="REAL_HISTORICAL">Historical (CIC-IDS)</option>
              <option value="SYNTHETIC">Synthetic Demo Only</option>
            </select>
          </div>
        </div>

        <div className="text-slate-400 font-mono text-[11px]">
          Showing {filteredEvents.length} of {allEvents.length} events
        </div>
      </div>

      {/* Main Events Telemetry Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
        <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Security Events Stream
            </h3>
          </div>
          <div className="text-slate-400 text-[11px] font-mono">
            Click any row to inspect complete payload &amp; attribution
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Attack Category</th>
                <th className="py-2.5 px-3">Source IP &amp; Port</th>
                <th className="py-2.5 px-3">Destination IP</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">CVE Ref</th>
                <th className="py-2.5 px-3">Provenance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 font-mono">
              {filteredEvents.length > 0 ? (
                filteredEvents.slice(0, 30).map((evt: any) => {
                  const isSim = evt.dataset_source === 'SIMULATED_DEMO' || evt.event_id?.startsWith('SIM-');
                  const isCrit = evt.severity === 'CRITICAL';
                  const isHigh = evt.severity === 'HIGH';

                  return (
                    <tr
                      key={evt.event_id}
                      onClick={() => setSelectedEvent(evt)}
                      className={`cursor-pointer hover:bg-slate-800/60 transition-colors ${
                        isCrit ? 'bg-rose-950/20' : isHigh ? 'bg-amber-950/15' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {evt.timestamp?.includes('T') ? evt.timestamp.replace('T', ' ').substring(0, 19) : evt.timestamp}
                      </td>
                      <td className="py-2.5 px-3 font-semibold text-slate-200 whitespace-nowrap">
                        {evt.event_id}
                      </td>
                      <td className="py-2.5 px-3 text-slate-100 font-sans font-medium">
                        {evt.attack_category || 'Unclassified'}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-300">
                        {evt.source_ip || 'N/A'}{evt.source_port ? `:${evt.source_port}` : ''}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {evt.destination_ip || evt.asset_id || 'N/A'}
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
                      <td className="py-2.5 px-3 text-purple-300 font-mono">
                        {evt.cve_id || <span className="text-slate-600">—</span>}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {isSim ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            SIMULATION
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
                    No matching security events found. Adjust your filters or click &quot;Start Simulation&quot; above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Drawer / Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-bold text-white font-mono">Event Details: {selectedEvent.event_id}</h3>
                  <p className="text-[11px] text-slate-400">{selectedEvent.timestamp}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs font-sans">
              {/* Top Meta Badges */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                  selectedEvent.severity === 'CRITICAL'
                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                    : selectedEvent.severity === 'HIGH'
                    ? 'bg-amber-950 text-amber-300 border border-amber-800'
                    : 'bg-slate-800 text-slate-300'
                }`}>
                  {selectedEvent.severity}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {selectedEvent.attack_category || 'Unclassified'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-800 text-slate-400 border border-slate-700">
                  Protocol: {selectedEvent.protocol || 'TCP'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-indigo-950 text-indigo-300 border border-indigo-800">
                  NIST: {selectedEvent.nist_function || 'DE.CM-1'}
                </span>
              </div>

              {/* Network Attribution Grid */}
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 grid grid-cols-2 gap-4 font-mono">
                <div>
                  <div className="text-[10px] text-slate-500 uppercase">Source Endpoint</div>
                  <div className="text-cyan-300 font-semibold text-xs mt-0.5">
                    {selectedEvent.source_ip || 'N/A'}:{selectedEvent.source_port || 'ephemeral'}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase">Destination Endpoint</div>
                  <div className="text-slate-200 font-semibold text-xs mt-0.5">
                    {selectedEvent.destination_ip || 'N/A'}:{selectedEvent.destination_port || '80/443'}
                  </div>
                </div>
              </div>

              {/* Description & Impact */}
              <div>
                <div className="text-slate-400 font-semibold text-[11px] mb-1">Description &amp; Telemetry Signature</div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 leading-relaxed font-mono text-[11px]">
                  {selectedEvent.description || 'Observed anomalous traffic pattern matched against CRISP IDS signatures.'}
                </div>
              </div>

              {/* Asset & CVE Links */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[10px] uppercase font-mono">Target Asset Mapping</span>
                  <div className="font-semibold text-white mt-1">
                    {selectedEvent.asset_id || 'prod-edge-web01.internal'}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[10px] uppercase font-mono">Associated CVE Reference</span>
                  <div className="font-mono font-semibold text-amber-300 mt-1">
                    {selectedEvent.cve_id || 'None directly associated'}
                  </div>
                </div>
              </div>

              {/* Provenance Footer */}
              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                <span>Data Provenance:</span>
                <span className="text-cyan-400 font-semibold">
                  {selectedEvent.dataset_source || 'SIMULATED_DEMO'}
                </span>
              </div>
            </div>

            <div className="px-6 py-3 border-t border-slate-800 bg-slate-950 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
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
