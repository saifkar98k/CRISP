import React, { useState, useEffect } from 'react';
import {
  Server,
  Zap,
  CheckCircle2,
  AlertCircle,
  Database,
  Layers,
  Send,
  RefreshCw,
  Clock,
  Shield,
  Activity,
  AlertTriangle,
  Radio,
  FileCode,
  Terminal,
} from 'lucide-react';

interface ProviderInfo {
  name: string;
  category: string;
  is_verified: boolean;
  verification_status: string;
  required_env_vars: string[];
  is_configured: boolean;
}

interface QueueStatus {
  status: string;
  capacity: number;
  current_depth: number;
  utilization_pct: number;
  workers_active: number;
  total_enqueued: number;
  total_processed: number;
  total_retries: number;
  total_dlq: number;
  backpressure_drops: number;
  duplicate_suppressions: number;
  queue_engine: string;
  redis_scale_out_ready: boolean;
}

export const EnterpriseIntegrationsView: React.FC = () => {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [queueStatus, setQueueStatus] = useState<QueueStatus | null>(null);
  const [dlqItems, setDlqItems] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [ingestStatusMessage, setIngestStatusMessage] = useState<string | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [provRes, qRes, dlqRes] = await Promise.all([
        fetch('/api/integrations/providers'),
        fetch('/api/pipeline/queue-status'),
        fetch('/api/pipeline/dlq?limit=10'),
      ]);

      if (provRes.ok) {
        const provData = await provRes.json();
        if (Array.isArray(provData)) setProviders(provData);
      }
      if (qRes.ok) {
        const qData = await qRes.json();
        setQueueStatus(qData);
      }
      if (dlqRes.ok) {
        const dlqData = await dlqRes.json();
        if (Array.isArray(dlqData)) setDlqItems(dlqData);
      }
    } catch (e) {
      console.error('Failed to load integration/queue status:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleTestIngest = async (providerKey: string, sampleData: any) => {
    try {
      setIngestStatusMessage(`Ingesting sample telemetry via ${providerKey}...`);
      const token = localStorage.getItem('crisp_token') || '';
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`/api/integrations/ingest/${providerKey}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(sampleData),
      });

      const json = await res.json();
      if (res.ok) {
        setIngestStatusMessage(`Success! Event enqueued (Queue ID: ${json.queue_item_id || json.signature}). Status: ${json.status}`);
        fetchData();
      } else {
        setIngestStatusMessage(`Ingest failed: ${json.error || json.message}`);
      }
    } catch (e: any) {
      setIngestStatusMessage(`Error: ${e.message}`);
    }
    setTimeout(() => setIngestStatusMessage(null), 5000);
  };

  return (
    <div className="space-y-6">
      {/* Real-Time Ingest Status Banner */}
      {ingestStatusMessage && (
        <div className="p-3 rounded-xl bg-cyan-950/80 border border-cyan-800 text-xs font-mono text-cyan-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            <span>{ingestStatusMessage}</span>
          </div>
          <button onClick={() => setIngestStatusMessage(null)} className="text-cyan-400 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

      {/* Asynchronous Queue Health & Backpressure Telemetry */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              <h3 className="font-bold text-white text-base tracking-tight">
                Scalable Ingestion Pipeline &amp; Event Queue
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                {queueStatus?.queue_engine || 'IN_MEMORY_BOUNDED_WITH_DLQ'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Bounded asynchronous queue with backpressure protection, retry policy, and Dead-Letter Queue (DLQ).
            </p>
          </div>

          <button
            onClick={fetchData}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 transition-colors shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Queue</span>
          </button>
        </div>

        {/* Queue Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-medium">Queue Depth</div>
            <div className="text-lg font-bold font-mono text-cyan-300 mt-0.5">
              {queueStatus?.current_depth ?? 0} / {queueStatus?.capacity ?? 5000}
            </div>
            <div className="w-full bg-slate-900 rounded-full h-1.5 mt-2 overflow-hidden border border-slate-800">
              <div
                className="bg-cyan-500 h-full rounded-full transition-all"
                style={{ width: `${Math.min(100, queueStatus?.utilization_pct ?? 0)}%` }}
              />
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-medium">Active Workers</div>
            <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
              {queueStatus?.workers_active ?? 2} Threads
            </div>
            <div className="text-[10px] text-slate-500 mt-1">Worker pool active</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-medium">Total Processed</div>
            <div className="text-lg font-bold font-mono text-white mt-0.5">
              {queueStatus?.total_processed ?? 0}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">Events committed to DB</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-medium">Duplicates Filtered</div>
            <div className="text-lg font-bold font-mono text-purple-400 mt-0.5">
              {queueStatus?.duplicate_suppressions ?? 0}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">Idempotent hash check</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-medium">Transient Retries</div>
            <div className="text-lg font-bold font-mono text-amber-400 mt-0.5">
              {queueStatus?.total_retries ?? 0}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">Exponential backoff</div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-medium">Dead-Letter Queue</div>
            <div className="text-lg font-bold font-mono text-rose-400 mt-0.5">
              {queueStatus?.total_dlq ?? 0}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">Max retries exceeded</div>
          </div>
        </div>

        {/* Deployment Trade-Off Banner */}
        <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 text-[11px] text-slate-400 flex items-start gap-2">
          <Terminal className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-slate-200">Architecture &amp; Scale-Out Note:</span>{' '}
            Currently running single-instance bounded queue with backpressure protection. Zero external infrastructure dependencies.
            For horizontally distributed multi-node clusters, setting <code className="text-cyan-300 font-mono">REDIS_URL</code> enables the Redis Streams distributed transport.
          </div>
        </div>
      </div>

      {/* 4 Controlled Enterprise Provider Adapters */}
      <div>
        <div className="mb-4">
          <h3 className="font-bold text-white text-base">Enterprise Telemetry Adapters</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Normalized provider ingestion pipeline with explicit verification status badges.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* 1. Syslog Adapter */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 font-bold">
                  LOG COLLECTOR
                </span>
                <h4 className="font-bold text-white text-sm mt-1">Syslog (RFC 5424 / RFC 3164 &amp; CEF)</h4>
              </div>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                <CheckCircle2 className="w-3 h-3" />
                <span>VERIFIED PARSER</span>
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Standard RFC 5424 parser with ArcSight CEF header &amp; key-value extension parsing. Extracts source IP, destination port, threat category, and maps syslog severity.
            </p>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300 truncate">
              CEF:0|CheckPoint|Firewall-1|R80|Drop|SYN Flood Attack|8|src=198.51.100.45 dst=10.0.4.15 dpt=443
            </div>

            <button
              onClick={() =>
                handleTestIngest('syslog', {
                  raw: 'CEF:0|CheckPoint|Firewall-1|R80|Drop|TCP Port Sweep Anomaly|7|src=198.51.100.88 dst=10.0.4.15 dpt=443 proto=TCP',
                })
              }
              className="w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-cyan-300 border border-slate-700 transition-colors flex items-center justify-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Ingest Test RFC 5424 / CEF Record</span>
            </button>
          </div>

          {/* 2. Splunk SIEM Adapter */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-bold">
                  SIEM INTEGRATION
                </span>
                <h4 className="font-bold text-white text-sm mt-1">Splunk SIEM (HTTP Event Collector)</h4>
              </div>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
                <AlertCircle className="w-3 h-3" />
                <span>UNVERIFIED (SIMULATED ADAPTER)</span>
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Splunk HEC webhook and search query adapter. Normalizes correlated search alerts and maps CIM network traffic data. Requires <code className="text-cyan-300 font-mono">SPLUNK_HEC_URL</code> and <code className="text-cyan-300 font-mono">SPLUNK_HEC_TOKEN</code> for live enterprise connection.
            </p>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300 truncate">
              {JSON.stringify({ event: { action: "Brute Force Auth Failure", src: "192.168.1.55", dest: "10.0.4.15", severity: "high" } })}
            </div>

            <button
              onClick={() =>
                handleTestIngest('splunk', {
                  event: {
                    action: 'Splunk Correlated: Privilege Escalation Attempt',
                    src: '10.0.99.88',
                    dest: '10.0.4.15',
                    dest_port: 443,
                    severity: 'critical',
                    sid: 'SPLUNK-ALERT-98214',
                  },
                })
              }
              className="w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-amber-300 border border-slate-700 transition-colors flex items-center justify-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Simulate Splunk HEC Ingestion</span>
            </button>
          </div>

          {/* 3. Tenable Nessus Vulnerability Scanner */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                  VULNERABILITY SCANNER
                </span>
                <h4 className="font-bold text-white text-sm mt-1">Tenable Nessus / Qualys VMDR</h4>
              </div>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                <CheckCircle2 className="w-3 h-3" />
                <span>VERIFIED PARSER</span>
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Normalizes exported Nessus JSON v2 and Qualys VMDR vulnerability scan reports. Correlates CVE IDs, CVSS v3 base metrics, and binds them to assets in the database.
            </p>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300 truncate">
              {JSON.stringify({ plugin_id: "155998", cve: "CVE-2021-44228", cvss: 10.0, host: "10.0.4.15", risk_factor: "Critical" })}
            </div>

            <button
              onClick={() =>
                handleTestIngest('nessus', {
                  plugin_id: '155998',
                  plugin_name: 'Apache Log4j Remote Code Execution',
                  cve: 'CVE-2021-44228',
                  cvss3_base_score: 10.0,
                  host: '10.0.4.15',
                  port: 443,
                  risk_factor: 'Critical',
                })
              }
              className="w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-emerald-300 border border-slate-700 transition-colors flex items-center justify-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Ingest Tenable Nessus Scan Report</span>
            </button>
          </div>

          {/* 4. CrowdStrike Falcon / AWS GuardDuty */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-bold">
                  ENDPOINT &amp; CLOUD EDR
                </span>
                <h4 className="font-bold text-white text-sm mt-1">CrowdStrike Falcon / AWS GuardDuty</h4>
              </div>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
                <AlertCircle className="w-3 h-3" />
                <span>UNVERIFIED (SIMULATED ADAPTER)</span>
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Parses CrowdStrike Falcon Streaming API detections and AWS GuardDuty CloudTrail anomaly findings. Requires <code className="text-cyan-300 font-mono">FALCON_CLIENT_ID</code> and <code className="text-cyan-300 font-mono">FALCON_CLIENT_SECRET</code> for live enterprise tenant connection.
            </p>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300 truncate">
              {JSON.stringify({ detection_id: "ldt:abc123", tactic: "Credential Access", hostname: "prod-dc-01", severity: "High" })}
            </div>

            <button
              onClick={() =>
                handleTestIngest('crowdstrike', {
                  detection_id: 'ldt:cs-alert-7729',
                  tactic: 'Defense Evasion: Process Injection Detected',
                  hostname: 'prod-edge-web01.internal',
                  local_ip: '10.0.4.15',
                  remote_ip: '198.51.100.99',
                  severity: 'Critical',
                })
              }
              className="w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-purple-300 border border-slate-700 transition-colors flex items-center justify-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Simulate CrowdStrike Falcon EDR Ingest</span>
            </button>
          </div>
        </div>
      </div>

      {/* Dead-Letter Queue (DLQ) Inspector Table */}
      {dlqItems.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900 border border-rose-900/60 space-y-3 shadow-xl">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            <h4 className="font-bold text-white text-sm">Dead-Letter Queue (DLQ) Records</h4>
          </div>
          <p className="text-xs text-slate-400">
            Unprocessable records that failed validation or exceeded max retries. Preserved for inspection and replay.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead className="bg-slate-950 text-slate-400 font-mono text-[11px]">
                <tr>
                  <th className="p-2">DLQ ID</th>
                  <th className="p-2">Timestamp</th>
                  <th className="p-2">Provider</th>
                  <th className="p-2">Retries</th>
                  <th className="p-2">Error Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {dlqItems.map((item) => (
                  <tr key={item.dlq_id}>
                    <td className="p-2 font-mono text-rose-300">{item.dlq_id}</td>
                    <td className="p-2 font-mono text-slate-400">{item.timestamp?.substring(0, 19)}</td>
                    <td className="p-2 font-mono text-slate-300">{item.source_provider}</td>
                    <td className="p-2 font-mono text-amber-300">{item.retry_count}</td>
                    <td className="p-2 text-rose-300 truncate max-w-xs">{item.error_message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
