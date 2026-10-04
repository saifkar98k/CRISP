import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useCrisp } from '../context/CrispContext';
import { SecurityEvent } from '../types/schemas';
import { DataSourceBadge } from '../components/DataSourceBadge';
import { CSVMappingModal } from '../components/CSVMappingModal';
import {
  Search,
  Filter,
  Zap,
  Download,
  Upload,
  RefreshCw,
  BarChart3,
  Calendar,
  Layers,
  Shield,
  Activity,
  Server,
  ArrowRight,
  Database,
  Radio,
  Clock,
  Terminal,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import Papa from 'papaparse';

interface EventAnalytics {
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  top_source_ips: { source_ip: string; count: number; max_severity: string; attack_category: string }[];
  top_dest_ports: { port: number; count: number; protocol: string }[];
  protocols: Record<string, number>;
  sources: Record<string, number>;
  over_time: { date: string; count: number; severity: string }[];
}

export const SecurityEventsView: React.FC = () => {
  const {
    securityEvents,
    simulateSingleEvent,
    isDemoModeActive,
    toggleDemoMode,
    provenanceFilter,
    setProvenanceFilter,
  } = useCrisp();

  // Filters requested by Phase 2 Step 3 specification
  const [dataSourceFilter, setDataSourceFilter] = useState<'ALL' | 'MOCK' | 'CIC-IDS2017'>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');
  const [search, setSearch] = useState<string>('');
  const [showAnalytics, setShowAnalytics] = useState<boolean>(true);
  const [isCsvModalOpen, setIsCsvModalOpen] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Live database analytics
  const [analytics, setAnalytics] = useState<EventAnalytics | null>(null);
  const [isLoadingAnalytics, setIsLoadingAnalytics] = useState(false);
  const [isImportingCic, setIsImportingCic] = useState(false);
  const [importSummary, setImportSummary] = useState<any | null>(null);
  const [dbEvents, setDbEvents] = useState<SecurityEvent[]>([]);

  // Fetch real database records and analytics from API
  const loadDatabaseData = useCallback(async () => {
    setIsLoadingAnalytics(true);
    try {
      const [analyticsRes, eventsRes] = await Promise.all([
        fetch('/api/events/analytics'),
        fetch('/api/events?limit=200'),
      ]);

      if (analyticsRes.ok) {
        const data = await analyticsRes.json();
        setAnalytics(data);
      }

      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        if (Array.isArray(eventsData) && eventsData.length > 0) {
          const mapped: SecurityEvent[] = eventsData.map((e: any) => ({
            id: e.event_id || e.id,
            timestamp: e.timestamp,
            sourceIp: e.source_ip,
            destinationIp: e.destination_ip,
            sourcePort: e.source_port,
            destinationPort: e.destination_port,
            protocol: e.protocol,
            attackCategory: e.attack_category || e.crisp_attack_category || 'Unclassified',
            originalAttackLabel: e.original_attack_label,
            crispAttackCategory: e.crisp_attack_category,
            severity: e.severity,
            description: e.description,
            assetId: e.asset_id,
            nistFunction: e.nist_function,
            relatedCveId: e.cve_id,
            status: e.status || 'HISTORICAL_RECORD',
            dataSource: e.dataset_source === 'MOCK' ? 'SYNTHETIC_DEMO' : 'CIC-IDS2017',
            datasetSource: e.dataset_source,
            isRealData: e.dataset_source !== 'MOCK',
            crispRiskScore: e.crisp_risk_score,
          }));
          setDbEvents(mapped);
        }
      }
    } catch (err) {
      console.error('Failed to load database events:', err);
    } finally {
      setIsLoadingAnalytics(false);
    }
  }, []);

  useEffect(() => {
    loadDatabaseData();
  }, [loadDatabaseData]);

  // Handle on-demand CIC-IDS2017 import
  const handleImportCicDataset = async () => {
    setIsImportingCic(true);
    try {
      const res = await fetch('/api/datasets/cic-ids2017/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 10000 }),
      });
      const data = await res.json();
      setImportSummary(data);
      await loadDatabaseData();
    } catch (err) {
      console.error('Import failed:', err);
    } finally {
      setIsImportingCic(false);
    }
  };

  // Combine DB events with local memory events
  const allEvents = useMemo(() => {
    const list = [...dbEvents];
    const seen = new Set(list.map((e) => e.id));
    for (const evt of securityEvents) {
      if (!seen.has(evt.id)) {
        list.push(evt);
        seen.add(evt.id);
      }
    }
    return list;
  }, [dbEvents, securityEvents]);

  // Unique categories in dataset
  const availableCategories = useMemo(() => {
    const set = new Set<string>();
    allEvents.forEach((e) => {
      if (e.attackCategory) set.add(e.attackCategory);
    });
    return Array.from(set).sort();
  }, [allEvents]);

  // Unique protocols
  const availableProtocols = useMemo(() => {
    const set = new Set<string>();
    allEvents.forEach((e) => {
      if (e.protocol) set.add(e.protocol);
    });
    return Array.from(set).sort();
  }, [allEvents]);

  // Apply all filters strictly
  const filteredEvents = useMemo(() => {
    return allEvents.filter((e) => {
      // 1. Data Source Filter
      if (dataSourceFilter === 'MOCK' && e.isRealData) return false;
      if (dataSourceFilter === 'CIC-IDS2017' && (!e.isRealData || (e.datasetSource && e.datasetSource !== 'CIC-IDS2017'))) return false;

      // Provenance global filter
      if (provenanceFilter === 'REAL_ONLY' && !e.isRealData) return false;
      if (provenanceFilter === 'SYNTHETIC_ONLY' && e.isRealData) return false;

      // 2. Attack Category Filter
      if (categoryFilter !== 'ALL' && e.attackCategory !== categoryFilter) return false;

      // 3. Severity Filter
      if (severityFilter !== 'ALL' && e.severity !== severityFilter) return false;

      // 4. Protocol Filter
      if (protocolFilter !== 'ALL' && e.protocol !== protocolFilter) return false;

      // 5. Date Range Filter
      if (startDate && e.timestamp) {
        if (e.timestamp.slice(0, 10) < startDate) return false;
      }
      if (endDate && e.timestamp) {
        if (e.timestamp.slice(0, 10) > endDate) return false;
      }

      // Search Query
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchId = e.id.toLowerCase().includes(q);
        const matchDesc = e.description?.toLowerCase().includes(q);
        const matchSrc = e.sourceIp?.includes(q);
        const matchDst = e.destinationIp?.includes(q);
        const matchLabel = e.originalAttackLabel?.toLowerCase().includes(q);
        const matchCve = e.relatedCveId?.toLowerCase().includes(q);
        return Boolean(matchId || matchDesc || matchSrc || matchDst || matchLabel || matchCve);
      }

      return true;
    });
  }, [allEvents, dataSourceFilter, provenanceFilter, categoryFilter, severityFilter, protocolFilter, startDate, endDate, search]);

  const exportCsv = () => {
    const csv = Papa.unparse(filteredEvents);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `crisp_security_events_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <span>Security Event Telemetry &amp; Threat Logs</span>
            </h2>
            <DataSourceBadge origin="CIC-IDS2017" size="sm" />
            <DataSourceBadge origin="SYNTHETIC_DEMO" size="sm" />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Historical public benchmark telemetry (CIC-IDS2017) and synthetic demonstration streams correlated via the CRISP Risk Engine.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleImportCicDataset}
            disabled={isImportingCic}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold shadow transition-colors disabled:opacity-50"
            title="Import or re-synchronize the CIC-IDS2017 historical benchmark dataset"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isImportingCic ? 'animate-spin' : ''}`} />
            <span>{isImportingCic ? 'Importing CIC-IDS2017...' : 'Sync CIC-IDS2017 Dataset'}</span>
          </button>

          <button
            onClick={() => setShowAnalytics(!showAnalytics)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showAnalytics ? 'Hide Analytics' : 'Show Analytics'}</span>
          </button>

          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Import Feedback Banner */}
      {importSummary && (
        <div className="p-4 rounded-xl bg-cyan-950/60 border border-cyan-800/80 text-xs text-cyan-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="space-y-1">
            <span className="font-bold flex items-center gap-1.5 text-cyan-100">
              <Database className="w-4 h-4 text-cyan-400" />
              CIC-IDS2017 Dataset Import Summary ({importSummary.dataset_name})
            </span>
            <div className="flex flex-wrap gap-4 text-slate-300 font-mono text-[11px]">
              <span>Rows Read: <strong className="text-white">{importSummary.rows_read}</strong></span>
              <span>Rows Imported: <strong className="text-emerald-400">{importSummary.rows_imported}</strong></span>
              <span>Duplicates Prevented: <strong className="text-amber-400">{importSummary.duplicates}</strong></span>
              <span>Invalid Rows: <strong className="text-rose-400">{importSummary.invalid_rows}</strong></span>
              <span>Total in DB: <strong className="text-cyan-300">{importSummary.total_stored}</strong></span>
            </div>
          </div>
          <button
            onClick={() => setImportSummary(null)}
            className="text-[11px] text-cyan-400 hover:text-cyan-200 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECURITY EVENT ANALYTICS (All 7 Visualizations Required by Spec) */}
      {/* ========================================================================= */}
      {showAnalytics && analytics && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <span>Security Event Analytics (Queried Live from SQLite)</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">
              Database Total: {Object.values(analytics.sources).reduce((a, b) => a + b, 0)} events
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* 1. Attack Category Distribution */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                <span>Attack Categories</span>
                <span className="text-[10px] text-cyan-400 font-normal">Top Categories</span>
              </h4>
              <div className="space-y-2">
                {Object.entries(analytics.by_category).slice(0, 5).map(([cat, count]) => {
                  const total = Object.values(analytics.by_category).reduce((a, b) => a + b, 0) || 1;
                  const pct = Math.round((count / total) * 100);
                  return (
                    <div key={cat} className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-300 truncate max-w-[170px]" title={cat}>{cat}</span>
                        <span className="font-mono text-cyan-400 font-bold">{count} ({pct}%)</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${pct}%` }}></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 2. Severity Distribution */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                <span>Severity Distribution</span>
                <span className="text-[10px] text-slate-400 font-normal">CRISP Classified</span>
              </h4>
              <div className="space-y-2">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map((sev) => {
                  const count = analytics.by_severity[sev] || 0;
                  const total = Object.values(analytics.by_severity).reduce((a, b) => a + b, 0) || 1;
                  const pct = Math.round((count / total) * 100);
                  const color =
                    sev === 'CRITICAL'
                      ? 'bg-rose-500 text-rose-400'
                      : sev === 'HIGH'
                      ? 'bg-amber-500 text-amber-400'
                      : sev === 'MEDIUM'
                      ? 'bg-yellow-500 text-yellow-400'
                      : sev === 'LOW'
                      ? 'bg-emerald-500 text-emerald-400'
                      : 'bg-blue-500 text-blue-400';

                  return (
                    <div key={sev} className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-300">{sev}</span>
                        <span className="font-mono font-bold">{count} ({pct}%)</span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className={`h-full ${color.split(' ')[0]} rounded-full`} style={{ width: `${pct}%` }}></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 3. Dataset vs Synthetic Event Counts */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                <span>Data Provenance</span>
                <span className="text-[10px] text-emerald-400 font-normal">Audited</span>
              </h4>
              <div className="space-y-3 pt-1">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-400 uppercase">Historical Public Dataset</div>
                  <div className="text-xl font-bold font-mono text-cyan-400 mt-0.5">
                    {analytics.sources['CIC-IDS2017'] || 0} events
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Source: UNB CIC-IDS2017 benchmark</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-400 uppercase">Synthetic Demo Events</div>
                  <div className="text-xl font-bold font-mono text-purple-400 mt-0.5">
                    {analytics.sources['MOCK'] || 0} events
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Source: Controlled local test stream</div>
                </div>
              </div>
            </div>

            {/* 4. Top Targeted Ports & Protocols */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                <span>Top Destination Ports</span>
                <span className="text-[10px] text-slate-400 font-normal">Network Flows</span>
              </h4>
              <div className="space-y-1.5 text-xs font-mono">
                {analytics.top_dest_ports.slice(0, 4).map((p) => (
                  <div key={p.port} className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-200">
                      Port <strong className="text-cyan-300">{p.port}</strong> ({p.protocol})
                    </span>
                    <span className="text-slate-400 text-[11px] font-bold">{p.count} hits</span>
                  </div>
                ))}
              </div>
              <div className="pt-1 flex gap-2 text-[11px] text-slate-400 font-mono">
                <span>Protocols:</span>
                {Object.entries(analytics.protocols).map(([proto, count]) => (
                  <span key={proto} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 text-[10px]">
                    {proto}: {count}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Attacks Over Time & Top Source IPs Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* 5. Attacks Over Time */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                <span>Attacks Over Time</span>
                <span className="text-[10px] text-slate-400 font-normal">Daily Flow Aggregations</span>
              </h4>
              <div className="space-y-2">
                {analytics.over_time.slice(0, 6).map((ot, idx) => (
                  <div key={`${ot.date}-${ot.severity}-${idx}`} className="flex items-center justify-between text-xs font-mono p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-300 flex items-center gap-2">
                      <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                      {ot.date}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {ot.severity}
                      </span>
                      <span className="font-bold text-cyan-400">{ot.count} flows</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 6. Top Attacking Source IPs */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                <span>Top Source IPs (Attacker Entities)</span>
                <span className="text-[10px] text-slate-400 font-normal">Ranked by Volume</span>
              </h4>
              <div className="space-y-2">
                {analytics.top_source_ips.slice(0, 5).map((ip) => (
                  <div key={ip.source_ip} className="flex items-center justify-between text-xs font-mono p-2 rounded bg-slate-950 border border-slate-800/80">
                    <div>
                      <span className="text-cyan-300 font-bold">{ip.source_ip}</span>
                      <div className="text-[10px] text-slate-500 font-sans">{ip.attack_category}</div>
                    </div>
                    <div className="text-right">
                      <span className="font-bold text-white">{ip.count} events</span>
                      <div className="text-[10px] text-rose-400 font-sans">{ip.max_severity}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* FILTER BAR (Data Source, Attack Category, Severity, Protocol, Date Range) */}
      {/* ========================================================================= */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Interactive Telemetry Filters</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {/* 1. DATA SOURCE FILTER */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Data Source
            </label>
            <select
              value={dataSourceFilter}
              onChange={(e) => setDataSourceFilter(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            >
              <option value="ALL">All Sources</option>
              <option value="CIC-IDS2017">CIC-IDS2017 (Real Historical)</option>
              <option value="MOCK">Mock (Synthetic Demo)</option>
            </select>
          </div>

          {/* 2. ATTACK CATEGORY FILTER */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Attack Category
            </label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            >
              <option value="ALL">All Categories</option>
              {availableCategories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>

          {/* 3. SEVERITY FILTER */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              CRISP Severity
            </label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFORMATIONAL">INFORMATIONAL</option>
            </select>
          </div>

          {/* 4. PROTOCOL FILTER */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Protocol
            </label>
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            >
              <option value="ALL">All Protocols</option>
              {availableProtocols.map((proto) => (
                <option key={proto} value={proto}>
                  {proto}
                </option>
              ))}
            </select>
          </div>

          {/* 5. START DATE FILTER */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              Start Date
            </label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            />
          </div>

          {/* 6. END DATE FILTER */}
          <div>
            <label className="block text-[10px] font-semibold text-slate-400 uppercase mb-1">
              End Date
            </label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none"
            />
          </div>
        </div>

        {/* Search Bar & Reset */}
        <div className="flex flex-col sm:flex-row gap-2 pt-2">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Search by IP address, port, original label, CVE, or description..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 font-mono placeholder:font-sans focus:border-cyan-500 outline-none"
            />
          </div>

          {(dataSourceFilter !== 'ALL' || categoryFilter !== 'ALL' || severityFilter !== 'ALL' || protocolFilter !== 'ALL' || startDate || endDate || search) && (
            <button
              onClick={() => {
                setDataSourceFilter('ALL');
                setCategoryFilter('ALL');
                setSeverityFilter('ALL');
                setProtocolFilter('ALL');
                setStartDate('');
                setEndDate('');
                setSearch('');
              }}
              className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* EVENTS TABLE */}
      {/* ========================================================================= */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-xs font-bold text-slate-200 uppercase font-mono">
              Filtered Records: {filteredEvents.length} of {allEvents.length}
            </span>
          </div>

          {/* Synthetic Demo Simulator controls (Preserved) */}
          <div className="flex items-center gap-2">
            <button
              onClick={simulateSingleEvent}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-purple-900/60 hover:bg-purple-800 text-purple-200 text-xs font-semibold border border-purple-700/60 transition-colors"
              title="Inject one synthetic test event for viva demo"
            >
              <Zap className="w-3.5 h-3.5 text-purple-400" />
              <span>Inject Demo Event</span>
            </button>

            <button
              onClick={toggleDemoMode}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${
                isDemoModeActive
                  ? 'bg-rose-900/60 border-rose-700 text-rose-200'
                  : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
              }`}
            >
              <Radio className={`w-3.5 h-3.5 ${isDemoModeActive ? 'text-rose-400 animate-pulse' : 'text-slate-400'}`} />
              <span>{isDemoModeActive ? 'Stop Stream' : 'Live Stream'}</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 font-semibold uppercase border-b border-slate-800 font-sans">
              <tr>
                <th className="py-3 px-4">Event ID / Time</th>
                <th className="py-3 px-4">Data Provenance</th>
                <th className="py-3 px-4">Attack Category (Mapped)</th>
                <th className="py-3 px-4">Original Dataset Label</th>
                <th className="py-3 px-4">Flow (Source &rarr; Dest:Port)</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4 text-right">CRISP Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-sans text-xs">
                    No security events match the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredEvents.slice(0, 100).map((e) => {
                  const sevColor =
                    e.severity === 'CRITICAL'
                      ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                      : e.severity === 'HIGH'
                      ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                      : e.severity === 'MEDIUM'
                      ? 'bg-yellow-950/80 text-yellow-300 border-yellow-800'
                      : e.severity === 'LOW'
                      ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                      : 'bg-blue-950/80 text-blue-300 border-blue-800';

                  return (
                    <tr
                      key={e.id}
                      onClick={() => setSelectedEvent(e)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      {/* Event ID & Timestamp */}
                      <td className="py-3 px-4">
                        <div className="font-bold text-slate-100 truncate max-w-[170px]" title={e.id}>
                          {e.id}
                        </div>
                        <div className="text-[10px] text-slate-400">
                          {e.timestamp ? e.timestamp.replace('T', ' ').replace('Z', '') : 'N/A'}
                        </div>
                      </td>

                      {/* Data Source Badge */}
                      <td className="py-3 px-4">
                        <DataSourceBadge
                          origin={e.datasetSource || e.dataSource}
                          isRealData={e.isRealData}
                          size="sm"
                        />
                      </td>

                      {/* Attack Category */}
                      <td className="py-3 px-4 font-sans">
                        <span className="font-semibold text-slate-200">{e.attackCategory}</span>
                        {e.nistFunction && (
                          <div className="text-[10px] text-cyan-400 font-mono">NIST: {e.nistFunction}</div>
                        )}
                      </td>

                      {/* Original Attack Label */}
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-300">
                        {e.originalAttackLabel || e.attackCategory}
                      </td>

                      {/* Flow Source -> Dest */}
                      <td className="py-3 px-4 text-[11px]">
                        <div className="text-slate-300">
                          {e.sourceIp || 'Unknown'}{e.sourcePort ? `:${e.sourcePort}` : ''}
                        </div>
                        <div className="text-slate-500 flex items-center gap-1">
                          <ArrowRight className="w-2.5 h-2.5 text-slate-600" />
                          <span>{e.destinationIp || 'Unknown'}{e.destinationPort ? `:${e.destinationPort}` : ''}</span>
                        </div>
                      </td>

                      {/* Protocol */}
                      <td className="py-3 px-4 font-mono text-[11px]">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                          {e.protocol || 'TCP'}
                        </span>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-4">
                        <span className={`inline-block font-sans font-semibold text-[10px] px-2 py-0.5 rounded border ${sevColor}`}>
                          {e.severity}
                        </span>
                      </td>

                      {/* CRISP Risk Score */}
                      <td className="py-3 px-4 text-right">
                        <span className="font-bold text-sm text-cyan-300 font-mono">
                          {e.crispRiskScore !== undefined ? e.crispRiskScore.toFixed(1) : '—'}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">{selectedEvent.id}</h3>
                  <DataSourceBadge origin={selectedEvent.datasetSource || selectedEvent.dataSource} size="sm" />
                </div>
                <p className="text-xs text-slate-400 mt-1">{selectedEvent.timestamp}</p>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase">Original Benchmark Label</span>
                <div className="font-mono text-cyan-300 font-bold">{selectedEvent.originalAttackLabel || selectedEvent.attackCategory}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase">CRISP Classified Category</span>
                <div className="font-mono text-white font-bold">{selectedEvent.attackCategory}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase">Source Entity</span>
                <div className="font-mono text-slate-300">{selectedEvent.sourceIp || 'N/A'}:{selectedEvent.sourcePort || 'N/A'}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-500 uppercase">Destination Target</span>
                <div className="font-mono text-slate-300">{selectedEvent.destinationIp || 'N/A'}:{selectedEvent.destinationPort || 'N/A'} ({selectedEvent.protocol || 'TCP'})</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-xs">
              <span className="text-[10px] text-slate-500 uppercase">Telemetry Narrative</span>
              <p className="text-slate-300 leading-relaxed">{selectedEvent.description}</p>
            </div>

            {selectedEvent.relatedCveId && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 text-xs text-rose-300 flex items-center justify-between">
                <span>Associated Vulnerability: <strong>{selectedEvent.relatedCveId}</strong></span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-rose-900 text-rose-100 font-bold">CVE Correlated</span>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CSV Mapping Modal */}
      <CSVMappingModal isOpen={isCsvModalOpen} onClose={() => setIsCsvModalOpen(false)} />
    </div>
  );
};
