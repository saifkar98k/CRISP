import express from 'express';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-memory server cache for API resilience
const serverCache = {
  cisaKev: null as any,
  cisaKevTimestamp: 0,
  nvdQueries: new Map<string, { data: any; timestamp: number }>(),
};

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
  });

  // CISA KEV Proxy with server-side caching (1 hour TTL)
  app.get('/api/cisa-kev', async (req, res) => {
    const ONE_HOUR = 60 * 60 * 1000;
    const now = Date.now();

    if (serverCache.cisaKev && now - serverCache.cisaKevTimestamp < ONE_HOUR) {
      return res.json(serverCache.cisaKev);
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 9000);

      const response = await fetch(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        {
          signal: controller.signal,
          headers: {
            'User-Agent': 'CRISP-Cyber-Risk-Intelligence-Engine/2.1',
            Accept: 'application/json',
          },
        }
      );
      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`CISA server returned ${response.status}`);
      }

      const json = await response.json();
      serverCache.cisaKev = json;
      serverCache.cisaKevTimestamp = now;
      return res.json(json);
    } catch (err: any) {
      console.warn('CISA KEV external fetch failed, checking fallback:', err.message);

      // Return cached if available
      if (serverCache.cisaKev) {
        return res.json(serverCache.cisaKev);
      }

      // Read pre-bundled fallback
      try {
        const fallbackPath = path.resolve(__dirname, 'src', 'data', 'curated_cve_catalog.json');
        if (fs.existsSync(fallbackPath)) {
          const raw = fs.readFileSync(fallbackPath, 'utf8');
          const vulns = JSON.parse(raw);
          const simulatedKev = {
            title: 'CISA Known Exploited Vulnerabilities Catalog (Embedded Fallback)',
            dateReleased: new Date().toISOString(),
            count: vulns.filter((v: any) => v.isKnownExploited).length,
            vulnerabilities: vulns
              .filter((v: any) => v.isKnownExploited)
              .map((v: any) => ({
                cveID: v.id,
                vendorProject: v.kevVendorProject || 'Vendor',
                product: v.kevProduct || 'Product',
                vulnerabilityName: v.kevVulnerabilityName || v.title,
                dateAdded: v.kevDateAdded || '2023-01-01',
                shortDescription: v.description,
                requiredAction: v.kevRequiredAction || 'Apply updates per vendor instructions.',
                dueDate: v.kevDueDate || '2024-01-01',
              })),
          };
          return res.json(simulatedKev);
        }
      } catch (readErr) {
        console.error('Failed reading fallback:', readErr);
      }

      return res.status(502).json({ error: 'Failed to retrieve CISA KEV catalog' });
    }
  });

  // NVD API 2.0 Proxy with query parameter forwarding, rate limit backoff & caching
  app.get('/api/nvd', async (req, res) => {
    const { resultsPerPage = '15', startIndex = '0', cveId, keywordSearch } = req.query;
    const cacheKey = `${resultsPerPage}_${startIndex}_${cveId || ''}_${keywordSearch || ''}`;
    const TEN_MINUTES = 10 * 60 * 1000;
    const now = Date.now();

    const cached = serverCache.nvdQueries.get(cacheKey);
    if (cached && now - cached.timestamp < TEN_MINUTES) {
      return res.json(cached.data);
    }

    try {
      const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
      url.searchParams.set('resultsPerPage', String(Math.min(Number(resultsPerPage) || 15, 25)));
      url.searchParams.set('startIndex', String(startIndex));

      if (cveId && typeof cveId === 'string' && cveId.trim()) {
        url.searchParams.set('cveId', cveId.trim());
      } else if (keywordSearch && typeof keywordSearch === 'string' && keywordSearch.trim()) {
        url.searchParams.set('keywordSearch', keywordSearch.trim());
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 9000);

      const nvdHeaders: Record<string, string> = {
        'User-Agent': 'CRISP-Cyber-Risk-Intelligence-Engine/2.1',
        Accept: 'application/json',
      };
      if (process.env.NVD_API_KEY) {
        nvdHeaders['apiKey'] = process.env.NVD_API_KEY;
      }

      const response = await fetch(url.toString(), {
        signal: controller.signal,
        headers: nvdHeaders,
      });
      clearTimeout(timeout);

      if (response.status === 429 || response.status === 503) {
        throw new Error(`NVD API rate limit or service unavailable (HTTP ${response.status})`);
      }

      if (!response.ok) {
        throw new Error(`NVD API returned HTTP ${response.status}`);
      }

      const json = await response.json();
      serverCache.nvdQueries.set(cacheKey, { data: json, timestamp: now });
      return res.json(json);
    } catch (err: any) {
      console.warn('NVD external API query failed, falling back to curated real CVE snapshot:', err.message);

      // Gracefully fall back to local curated CVE catalog formatted as NVD 2.0 JSON
      try {
        const fallbackPath = path.resolve(__dirname, 'src', 'data', 'curated_cve_catalog.json');
        if (fs.existsSync(fallbackPath)) {
          const raw = fs.readFileSync(fallbackPath, 'utf8');
          let items: any[] = JSON.parse(raw);

          if (cveId && typeof cveId === 'string') {
            items = items.filter((i) => i.id.toLowerCase().includes(cveId.toLowerCase()));
          } else if (keywordSearch && typeof keywordSearch === 'string') {
            const q = keywordSearch.toLowerCase();
            items = items.filter(
              (i) =>
                i.id.toLowerCase().includes(q) ||
                i.title.toLowerCase().includes(q) ||
                i.description.toLowerCase().includes(q)
            );
          }

          // Format as NVD 2.0 schema
          const nvdFormatted = {
            resultsPerPage: items.length,
            startIndex: 0,
            totalResults: items.length,
            format: 'NVD_CVE',
            version: '2.0',
            timestamp: new Date().toISOString(),
            vulnerabilities: items.map((v) => ({
              cve: {
                id: v.id,
                sourceIdentifier: 'cve@mitre.org',
                published: v.publishedDate,
                lastModified: v.modifiedDate,
                vulnStatus: 'Analyzed',
                descriptions: [{ lang: 'en', value: v.description }],
                metrics: {
                  cvssMetricV31: [
                    {
                      source: 'nvd@nist.gov',
                      type: 'Primary',
                      cvssData: {
                        version: '3.1',
                        vectorString: v.cvssVector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        baseScore: v.cvssScore,
                        baseSeverity: v.severity,
                      },
                    },
                  ],
                },
                weaknesses: (v.cwe || []).map((c: string) => ({
                  source: 'nvd@nist.gov',
                  type: 'Primary',
                  description: [{ lang: 'en', value: c }],
                })),
                configurations: [
                  {
                    nodes: [
                      {
                        operator: 'OR',
                        negate: false,
                        cpeMatch: (v.affectedProducts || []).map((p: string) => ({
                          vulnerable: true,
                          criteria: `cpe:2.3:a:${p.replace(/\s+/g, '_')}:*`,
                        })),
                      },
                    ],
                  },
                ],
                references: (v.references || []).map((url: string) => ({
                  url,
                  source: 'cve@mitre.org',
                })),
              },
            })),
          };
          return res.json(nvdFormatted);
        }
      } catch (readErr) {
        console.error('Error reading curated fallback catalog:', readErr);
      }

      return res.status(502).json({ error: 'NVD API query failed and fallback unavailable' });
    }
  });

  // Historical CSV Dataset endpoint
  app.get('/api/datasets/historical', (req, res) => {
    const csvPath = path.resolve(__dirname, 'src', 'data', 'historical_security_events.csv');
    if (fs.existsSync(csvPath)) {
      res.setHeader('Content-Type', 'text/csv');
      return res.sendFile(csvPath);
    }
    return res.status(404).send('Historical dataset not found');
  });

  // NVD Synchronization API endpoint
  app.post('/api/nvd/sync', (req, res) => {
    const { resultsPerPage = 20, startIndex = 0, keyword, cve_id } = req.body || {};
    try {
      const pyCmd = `python3 -c "import json; from services.nvd_sync_service import sync_nvd; print(json.dumps(sync_nvd(resultsPerPage=${parseInt(resultsPerPage, 10)}, startIndex=${parseInt(startIndex, 10)}${keyword ? `, keyword='${keyword.replace(/'/g, "\\'")}'` : ''}${cve_id ? `, cve_id='${cve_id.replace(/'/g, "\\'")}'` : ''})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 25000 });
      
      // Parse last JSON line
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const stats = JSON.parse(lastLine);
      return res.json(stats);
    } catch (err: any) {
      console.error('NVD sync error:', err.message);
      return res.json({
        fetched: 0,
        inserted: 0,
        updated: 0,
        failed: 1,
        status: 'Error',
        error: err.message,
      });
    }
  });

  // NVD Status endpoint
  app.get('/api/nvd/status', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.nvd_sync_service import get_nvd_sync_status; print(json.dumps(get_nvd_sync_status()))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 5000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const status = JSON.parse(lastLine);
      return res.json(status);
    } catch (err: any) {
      return res.json({
        connection: 'Error',
        last_synchronization: null,
        total_nvd_vulnerabilities: 0,
        last_stats: { fetched: 0, inserted: 0, updated: 0, failed: 0 },
      });
    }
  });

  // NVD Stored Vulnerabilities endpoint
  app.get('/api/nvd/stored', (req, res) => {
    const { limit = 50, offset = 0, severity = 'ALL' } = req.query;
    try {
      const pyCmd = `python3 -c "import json; from services.nvd_sync_service import get_vulnerabilities; print(json.dumps(get_vulnerabilities(limit=${parseInt(String(limit), 10)}, offset=${parseInt(String(offset), 10)}, severity='${String(severity)}')))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 8000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const vulns = JSON.parse(lastLine);
      return res.json(vulns);
    } catch (err: any) {
      return res.json([]);
    }
  });

  // CISA KEV Synchronization API endpoint
  app.post('/api/cisa-kev/sync', (req, res) => {
    const { limit } = req.body || {};
    try {
      const pyCmd = `python3 -c "import json; from services.cisa_kev_sync_service import sync_cisa_kev; print(json.dumps(sync_cisa_kev(${limit ? `limit=${parseInt(limit, 10)}` : ''})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 30000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const stats = JSON.parse(lastLine);
      return res.json(stats);
    } catch (err: any) {
      console.error('CISA KEV sync error:', err.message);
      return res.json({
        fetched: 0,
        matched_nvd: 0,
        new_records: 0,
        updated_records: 0,
        failed: 1,
        status: 'Error',
        error: err.message,
      });
    }
  });

  // CISA KEV Status endpoint
  app.get('/api/cisa-kev/status', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.cisa_kev_sync_service import get_cisa_kev_sync_status; print(json.dumps(get_cisa_kev_sync_status()))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 5000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const status = JSON.parse(lastLine);
      return res.json(status);
    } catch (err: any) {
      return res.json({
        connection: 'Error',
        last_synchronization: null,
        total_known_exploited_stored: 0,
        local_crisp_vulnerabilities_in_kev: 0,
        last_stats: { fetched: 0, matched_nvd: 0, new_records: 0, updated_records: 0, failed: 0 },
      });
    }
  });

  // CISA KEV Stored Records endpoint
  app.get('/api/cisa-kev/stored', (req, res) => {
    const { limit = 50, offset = 0, vendor, product, search } = req.query;
    try {
      const pyCmd = `python3 -c "import json; from services.cisa_kev_sync_service import get_known_exploited_vulnerabilities; print(json.dumps(get_known_exploited_vulnerabilities(limit=${parseInt(String(limit), 10)}, offset=${parseInt(String(offset), 10)}${vendor ? `, vendor='${String(vendor).replace(/'/g, "\\'")}'` : ''}${product ? `, product='${String(product).replace(/'/g, "\\'")}'` : ''}${search ? `, search='${String(search).replace(/'/g, "\\'")}'` : ''})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 8000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const records = JSON.parse(lastLine);
      return res.json(records);
    } catch (err: any) {
      return res.json([]);
    }
  });

  // CIC-IDS2017 Raw Dataset CSV endpoint
  app.get('/api/datasets/cic-ids2017', (req, res) => {
    const customPath = process.env.SECURITY_DATASET_PATH;
    const defaultPath = path.resolve(__dirname, 'data', 'cic_ids2017_sample.csv');
    const targetPath = (customPath && fs.existsSync(customPath)) ? customPath : defaultPath;

    if (fs.existsSync(targetPath)) {
      res.setHeader('Content-Type', 'text/csv');
      return res.sendFile(targetPath);
    }
    return res.status(404).send('CIC-IDS2017 sample dataset not found');
  });

  // CIC-IDS2017 Dataset Info / Inspection metadata
  app.get('/api/datasets/cic-ids2017/info', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.providers.security_dataset_provider import SecurityDatasetProvider; print(json.dumps(SecurityDatasetProvider().get_dataset_info()))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 8000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const info = JSON.parse(lastLine);
      return res.json(info);
    } catch (err: any) {
      return res.json({
        file_name: 'cic_ids2017_sample.csv',
        exists: false,
        error: err.message,
      });
    }
  });

  // CIC-IDS2017 Dataset Import Endpoint
  app.post('/api/datasets/cic-ids2017/import', (req, res) => {
    const { limit, chunk_size, dataset_path } = req.body || {};
    try {
      const pyCmd = `python3 -c "import json; from services.security_event_service import import_dataset_into_db; print(json.dumps(import_dataset_into_db(${dataset_path ? `dataset_path='${dataset_path.replace(/'/g, "\\'")}', ` : ''}${limit ? `limit=${parseInt(limit, 10)}, ` : ''}${chunk_size ? `chunk_size=${parseInt(chunk_size, 10)}` : ''})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 35000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const stats = JSON.parse(lastLine);
      return res.json(stats);
    } catch (err: any) {
      console.error('Dataset import error:', err.message);
      return res.json({
        dataset_name: 'CIC-IDS2017',
        rows_read: 0,
        rows_imported: 0,
        rows_skipped: 0,
        duplicates: 0,
        invalid_rows: 0,
        status: 'Error',
        error: err.message,
      });
    }
  });

  // Security Events Analytics Aggregations Endpoint
  app.get('/api/events/analytics', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.security_event_service import get_attacks_by_category, get_attacks_by_severity, get_top_source_ips, get_top_destination_ports, get_protocol_distribution, get_source_distribution, get_attacks_over_time; print(json.dumps({'by_category': get_attacks_by_category(), 'by_severity': get_attacks_by_severity(), 'top_source_ips': get_top_source_ips(limit=10), 'top_dest_ports': get_top_destination_ports(limit=10), 'protocols': get_protocol_distribution(), 'sources': get_source_distribution(), 'over_time': get_attacks_over_time(limit=15)}))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 10000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const analytics = JSON.parse(lastLine);
      return res.json(analytics);
    } catch (err: any) {
      return res.json({
        by_category: {},
        by_severity: {},
        top_source_ips: [],
        top_dest_ports: [],
        protocols: {},
        sources: {},
        over_time: [],
      });
    }
  });

  // Security Events Filtered Query Endpoint
  app.get('/api/events', (req, res) => {
    const { dataset_source, category, severity, protocol, limit = 100, offset = 0 } = req.query;
    try {
      const pyCmd = `python3 -c "import json; from services.security_event_service import get_security_events_filtered; print(json.dumps(get_security_events_filtered(dataset_source=${dataset_source && dataset_source !== 'ALL' ? `'${String(dataset_source).replace(/'/g, "\\'")}'` : 'None'}, attack_category=${category && category !== 'ALL' ? `'${String(category).replace(/'/g, "\\'")}'` : 'None'}, severity=${severity && severity !== 'ALL' ? `'${String(severity).replace(/'/g, "\\'")}'` : 'None'}, protocol=${protocol && protocol !== 'ALL' ? `'${String(protocol).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)}, offset=${parseInt(String(offset), 10)})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 10000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const events = JSON.parse(lastLine);
      return res.json(events);
    } catch (err: any) {
      return res.json([]);
    }
  });

  // Correlation Engine Run Endpoint (Phase 2 Step 4)
  app.post('/api/correlation/run', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.correlation_engine import run_correlation; print(json.dumps(run_correlation()))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 25000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const result = JSON.parse(lastLine);
      return res.json(result);
    } catch (err: any) {
      console.error('Correlation execution error:', err.message);
      return res.json({
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        top_correlated_risks: [],
        top_affected_assets: [],
        top_vulnerabilities: [],
        error: err.message,
      });
    }
  });

  // Correlated Security Findings Query Endpoint
  app.get('/api/correlation/findings', (req, res) => {
    const { risk_level, asset_id, cve_id, limit = 100 } = req.query;
    try {
      const pyCmd = `python3 -c "import json; from services.correlation_engine import SecurityCorrelationEngine; print(json.dumps(SecurityCorrelationEngine().get_findings(risk_level=${risk_level && risk_level !== 'ALL' ? `'${String(risk_level).replace(/'/g, "\\'")}'` : 'None'}, asset_id=${asset_id && asset_id !== 'ALL' ? `'${String(asset_id).replace(/'/g, "\\'")}'` : 'None'}, cve_id=${cve_id && cve_id !== 'ALL' ? `'${String(cve_id).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const findings = JSON.parse(lastLine);
      return res.json(findings);
    } catch (err: any) {
      return res.json([]);
    }
  });

  // Correlation Summary Analytics Endpoint
  app.get('/api/correlation/summary', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.correlation_engine import SecurityCorrelationEngine; engine = SecurityCorrelationEngine(); print(json.dumps({'top_risks': engine.get_top_correlated_risks(5), 'top_assets': engine.get_top_affected_assets(5), 'top_vulnerabilities': engine.get_top_vulnerabilities_with_events(5)}))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const summary = JSON.parse(lastLine);
      return res.json(summary);
    } catch (err: any) {
      return res.json({ top_risks: [], top_assets: [], top_vulnerabilities: [] });
    }
  });

  // CRISP Multi-Factor Risk History Endpoint
  app.get('/api/risk/history', (req, res) => {
    const { asset, finding, level, limit = 100 } = req.query;
    try {
      const pyCmd = `python3 -c "import json; from services.risk_engine import get_risk_history; print(json.dumps(get_risk_history(asset=${asset && asset !== 'ALL' ? `'${String(asset).replace(/'/g, "\\'")}'` : 'None'}, finding=${finding && finding !== 'ALL' ? `'${String(finding).replace(/'/g, "\\'")}'` : 'None'}, level=${level && level !== 'ALL' ? `'${String(level).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const history = JSON.parse(lastLine);
      return res.json(history);
    } catch (err: any) {
      return res.json([]);
    }
  });

  // CRISP Risk Over Time Trend Endpoint
  app.get('/api/risk/trend', (req, res) => {
    const { asset, limit = 50 } = req.query;
    try {
      const pyCmd = `python3 -c "import json; from services.risk_engine import get_risk_over_time_trend; print(json.dumps(get_risk_over_time_trend(asset=${asset && asset !== 'ALL' ? `'${String(asset).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const trend = JSON.parse(lastLine);
      return res.json(trend);
    } catch (err: any) {
      return res.json([]);
    }
  });

  // CRISP Real-Time Risk Score Calculator Endpoint
  app.post('/api/risk/calculate', (req, res) => {
    try {
      const inputData = JSON.stringify(req.body || {});
      const pyCmd = `python3 -c "import sys, json; from services.risk_engine import calculate_final_risk; data = json.load(sys.stdin); print(json.dumps(calculate_final_risk(**data)))"`;
      const stdout = execSync(pyCmd, { input: inputData, encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const result = JSON.parse(lastLine);
      return res.json(result);
    } catch (err: any) {
      return res.status(400).json({ error: 'Calculation failed', details: err.message });
    }
  });

  // =========================================================================
  // CRISP Security Event Simulator & Live Monitoring Endpoints
  // =========================================================================

  let simulationTimer: NodeJS.Timeout | null = null;
  let simulationIntervalMs = 3000;
  let isSimulating = false;

  function runSimulationTick() {
    try {
      const pyCmd = `python3 -c "import json; from services.event_simulator import get_simulator; print(json.dumps(get_simulator().generate_event()))"`;
      execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
    } catch (e) {
      console.error('Simulation tick error:', e);
    }
  }

  // Live Monitoring Metrics Endpoint
  app.get('/api/simulator/live-stats', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.event_simulator import get_simulator; print(json.dumps(get_simulator().get_live_monitoring_stats()))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const stats = JSON.parse(lastLine);
      // Keep running state in sync with server timer
      stats.simulation_status = {
        is_running: isSimulating,
        interval_seconds: simulationIntervalMs / 1000,
        events_per_minute: isSimulating ? Math.round(60000 / simulationIntervalMs) : stats.events_per_minute,
      };
      return res.json(stats);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to fetch live stats', details: err.message });
    }
  });

  // Simulator Status Endpoint
  app.get('/api/simulator/status', (req, res) => {
    return res.json({
      is_running: isSimulating,
      interval_seconds: simulationIntervalMs / 1000,
      events_per_minute: isSimulating ? Math.round(60000 / simulationIntervalMs) : 0,
      simulation_mode: true,
      label: 'SIMULATION MODE',
    });
  });

  // Start Simulation Loop
  app.post('/api/simulator/start', (req, res) => {
    const { speedSeconds = 3.0 } = req.body || {};
    simulationIntervalMs = Math.max(500, Number(speedSeconds) * 1000);
    if (simulationTimer) {
      clearInterval(simulationTimer);
    }
    isSimulating = true;
    // Trigger immediate first event
    runSimulationTick();
    simulationTimer = setInterval(runSimulationTick, simulationIntervalMs);

    return res.json({
      status: 'running',
      interval_seconds: simulationIntervalMs / 1000,
      events_per_minute: Math.round(60000 / simulationIntervalMs),
      simulation_mode: true,
      message: 'Controlled security event simulation is now active.',
    });
  });

  // Stop Simulation Loop
  app.post('/api/simulator/stop', (req, res) => {
    if (simulationTimer) {
      clearInterval(simulationTimer);
      simulationTimer = null;
    }
    isSimulating = false;
    return res.json({
      status: 'stopped',
      simulation_mode: true,
      message: 'Controlled simulation halted.',
    });
  });

  // Generate Single Simulation Event on Demand
  app.post('/api/simulator/generate', (req, res) => {
    try {
      const { type } = req.body || {};
      const inputData = JSON.stringify({ type: type || null });
      const pyCmd = `python3 -c "import sys, json; from services.event_simulator import get_simulator; data = json.load(sys.stdin); etype = data.get('type'); print(json.dumps(get_simulator().generate_event(etype)))"`;
      const stdout = execSync(pyCmd, { input: inputData, encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const result = JSON.parse(lastLine);
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to generate event', details: err.message });
    }
  });

  // =========================================================================
  // CRISP RAG Knowledge Base Endpoints (ChromaDB Foundation)
  // =========================================================================

  // Knowledge Base Stats
  app.get('/api/rag/stats', (req, res) => {
    try {
      const pyCmd = `python3 -c "import json; from services.rag.indexer import get_index_stats; print(json.dumps(get_index_stats()))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to get RAG stats', details: err.message });
    }
  });

  // Semantic Retrieval Endpoint
  app.post('/api/rag/query', (req, res) => {
    try {
      const payload = JSON.stringify(req.body || {});
      const pyCmd = `python3 -c "import sys, json; from services.rag.retriever import retrieve; d = json.load(sys.stdin); q = d.get('query', ''); c = d.get('collection'); n = int(d.get('n_results', 5)); f = d.get('filters') or d.get('where'); res = retrieve(q, filters=f, n_results=n, collection=c); print(json.dumps(res if isinstance(res, (list, dict)) else {'message': res, 'results': []}))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 25000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'RAG retrieval failed', details: err.message });
    }
  });

  // Trigger Knowledge Base Synchronization / Indexing
  app.post('/api/rag/index', (req, res) => {
    try {
      const payload = JSON.stringify(req.body || {});
      const pyCmd = `python3 -c "import sys, json; from services.rag.indexer import index_all, index_vulnerabilities, index_kev, index_nist, index_findings, index_assets, index_incidents; d = json.load(sys.stdin); domain = d.get('domain', 'all'); limit = d.get('limit'); res = index_vulnerabilities(limit=limit) if domain == 'vulnerabilities' else (index_kev(limit=limit) if domain == 'kev' else (index_nist() if domain == 'nist' else (index_findings(limit=limit) if domain == 'findings' else (index_assets() if domain == 'assets' else index_all(vuln_limit=limit, kev_limit=limit, incident_limit=limit))))); print(json.dumps(res))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 60000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'Indexing failed', details: err.message });
    }
  });

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CRISP Cyber Risk Engine listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
