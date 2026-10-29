import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import path from 'path';
import fs from 'fs';
import { execSync, spawn } from 'child_process';
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

// Map of active investigation child processes for real-time cancellation
const activeProcesses = new Map<string, any>();

// Cross-platform Python executable detection (supports Windows 'python' and Linux/macOS 'python3')
function resolvePythonBinary(): string {
  if (process.env.PYTHON_BIN) return process.env.PYTHON_BIN;
  try {
    execSync('python3 --version', { stdio: 'ignore' });
    return 'python3';
  } catch {
    try {
      execSync('python --version', { stdio: 'ignore' });
      return 'python';
    } catch {
      return 'python3';
    }
  }
}
const PYTHON_BIN = resolvePythonBinary();

// Helper to execute Python Auth Service methods
function callAuthService(func: string, args: Record<string, any> = {}): any {
  const payload = JSON.stringify(args);
  const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.auth_service import auth_service; d = json.load(sys.stdin); fn = getattr(auth_service, '${func}'); res = fn(**d); print(json.dumps(res))"`;
  const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
  const lines = stdout.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
}

// Helper to execute Python Audit Service methods
function callAuditService(func: string, args: Record<string, any> = {}): any {
  const payload = JSON.stringify(args);
  const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.audit_service import audit_service; d = json.load(sys.stdin); fn = getattr(audit_service, '${func}'); res = fn(**d); print(json.dumps(res))"`;
  const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
  const lines = stdout.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
}

// Helper to execute Enterprise Ingestion Hub methods
function callIntegrationHub(func: string, args: Record<string, any> = {}): any {
  const payload = JSON.stringify(args);
  const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.providers.enterprise_adapters import integration_hub; d = json.load(sys.stdin); fn = getattr(integration_hub, '${func}'); res = fn(**d); print(json.dumps(res))"`;
  const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
  const lines = stdout.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
}

// Helper to execute Event Queue methods
function callEventQueue(func: string, args: Record<string, any> = {}): any {
  const payload = JSON.stringify(args);
  const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.pipeline.event_queue import event_queue; d = json.load(sys.stdin); fn = getattr(event_queue, '${func}'); res = fn(**d); print(json.dumps(res))"`;
  const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
  const lines = stdout.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Security Headers Middleware
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Strict Request Body Size Limits to Prevent DoS
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Helper to extract session or header user
  const extractUser = (req: express.Request): any => {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const rawToken = authHeader.substring(7).trim();
      try {
        const session = callAuthService('validate_session', { raw_token: rawToken });
        if (session) return session;
      } catch (e) {
        console.warn('Session validation error:', e);
      }
    }
    const headerRole = req.headers['x-user-role'];
    const headerEmail = req.headers['x-user-email'];
    if (headerRole && typeof headerRole === 'string') {
      return {
        user_id: 'USR-HEADER',
        email: (headerEmail as string) || 'saifkar98k@gmail.com',
        username: 'saifkar98k',
        role: headerRole.toUpperCase(),
        tenant_id: 'default_tenant',
        permissions: ['investigate_swarm', 'create_remediations', 'verify_remediations'],
      };
    }
    // Default active operator
    return {
      user_id: 'USR-ANALYST-SK',
      email: 'saifkar98k@gmail.com',
      username: 'saifkar98k',
      role: 'SECURITY_ANALYST',
      tenant_id: 'default_tenant',
      permissions: ['investigate_swarm', 'create_remediations', 'verify_remediations'],
    };
  };

  // RBAC Middleware Guard
  const requireRole = (allowedRoles: string[]) => {
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
      const user = extractUser(req);
      (req as any).user = user;
      const normalizedRole = (user.role || '').toUpperCase();
      const hasPermission = allowedRoles.some((r) => r.toUpperCase() === normalizedRole);
      if (!hasPermission) {
        try {
          callAuditService('log_event', {
            actor_id: user.email,
            actor_role: user.role,
            tenant_id: user.tenant_id,
            action: 'ACCESS_DENIED',
            target_type: 'ENDPOINT',
            target_id: req.path,
            result: 'DENIED',
            ip_address: req.ip,
            details: { method: req.method, required_roles: allowedRoles },
          });
        } catch (e) {}
        return res.status(403).json({
          error: `Forbidden: role '${user.role}' lacks sufficient privileges for this operation. Required: ${allowedRoles.join(', ')}`,
          code: 'FORBIDDEN',
        });
      }
      next();
    };
  };

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      version: '2.2.0',
      time: new Date().toISOString(),
      security_mode: 'ENTERPRISE_RBAC_ACTIVE',
    });
  });

  // =========================================================================
  // Authentication & Session Endpoints
  // =========================================================================

  app.post('/api/auth/login', (req, res) => {
    try {
      const { identifier, password } = req.body || {};
      const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
      const userAgent = req.headers['user-agent'] || 'Unknown Client';
      const result = callAuthService('authenticate', {
        identifier,
        password,
        ip_address: ip,
        user_agent: userAgent,
      });
      if (!result.success) {
        const statusCode = result.code === 'RATE_LIMITED' ? 429 : 401;
        return res.status(statusCode).json(result);
      }
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ success: false, error: 'Authentication internal error', details: err.message });
    }
  });

  app.post('/api/auth/logout', (req, res) => {
    try {
      const authHeader = req.headers['authorization'] || '';
      const token = req.body?.token || (authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '');
      const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
      const success = callAuthService('logout', { raw_token: token, ip_address: ip });
      return res.json({ success, message: success ? 'Session revoked successfully.' : 'No active session found.' });
    } catch (err: any) {
      return res.status(500).json({ success: false, error: 'Logout failed', details: err.message });
    }
  });

  app.get('/api/auth/me', (req, res) => {
    const user = extractUser(req);
    return res.json({ user, authenticated: true });
  });

  app.get('/api/auth/users', requireRole(['ADMIN', 'SECURITY_ADMIN']), (req, res) => {
    try {
      const users = callAuthService('list_users');
      return res.json(users);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to list users', details: err.message });
    }
  });

  app.post('/api/auth/users', requireRole(['ADMIN']), (req, res) => {
    try {
      const { email, username, password, role, tenant_id = 'default_tenant' } = req.body || {};
      const actor = (req as any).user;
      const newUser = callAuthService('create_user', {
        email,
        username,
        password,
        role,
        tenant_id,
        creator_role: actor.role,
      });
      // Audit log user creation
      callAuditService('log_event', {
        actor_id: actor.email,
        actor_role: actor.role,
        action: 'USER_CREATED',
        target_type: 'USER',
        target_id: newUser.user_id,
        result: 'SUCCESS',
        tenant_id,
        details: { email, username, role },
      });
      return res.json({ success: true, user: newUser });
    } catch (err: any) {
      return res.status(400).json({ error: 'Failed to create user', details: err.message });
    }
  });

  // =========================================================================
  // Audit Logging Endpoints
  // =========================================================================

  app.get('/api/audit/logs', requireRole(['ADMIN', 'SECURITY_ADMIN', 'SECURITY_ANALYST', 'SOC_ANALYST']), (req, res) => {
    try {
      const { actor_id, action, target_type, result, limit = 50, offset = 0 } = req.query;
      const user = (req as any).user;
      const logs = callAuditService('query_logs', {
        actor_id: actor_id && actor_id !== 'ALL' ? actor_id : null,
        action: action && action !== 'ALL' ? action : null,
        target_type: target_type && target_type !== 'ALL' ? target_type : null,
        result: result && result !== 'ALL' ? result : null,
        tenant_id: user.role === 'ADMIN' ? null : user.tenant_id,
        limit: parseInt(String(limit), 10) || 50,
        offset: parseInt(String(offset), 10) || 0,
      });
      return res.json(logs);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to retrieve audit logs', details: err.message });
    }
  });

  app.get('/api/audit/stats', requireRole(['ADMIN', 'SECURITY_ADMIN', 'SECURITY_ANALYST', 'SOC_ANALYST']), (req, res) => {
    try {
      const stats = callAuditService('get_audit_stats');
      return res.json(stats);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to retrieve audit stats', details: err.message });
    }
  });

  // =========================================================================
  // Enterprise Data-Source Integration Endpoints
  // =========================================================================

  app.get('/api/integrations/providers', (req, res) => {
    try {
      const providers = callIntegrationHub('get_registered_providers');
      return res.json(providers);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to fetch integration providers', details: err.message });
    }
  });

  app.post('/api/integrations/ingest/:provider', requireRole(['ADMIN', 'SECURITY_ANALYST', 'SOC_ANALYST', 'SECURITY_ADMIN']), (req, res) => {
    try {
      const provider = req.params.provider;
      const rawData = req.body;
      const actor = (req as any).user;

      // Validate & Normalize via Adapter
      const ingestResult = callIntegrationHub('ingest_payload', { provider_key: provider, raw_data: rawData });
      if (!ingestResult.success) {
        return res.status(400).json(ingestResult);
      }

      if (ingestResult.status === 'DEDUPLICATED') {
        return res.json(ingestResult);
      }

      // Enqueue normalized event into bounded asynchronous event queue
      const queueRes = callEventQueue('enqueue', {
        payload: ingestResult.normalized_event,
        provider: ingestResult.normalized_event?.data_source || provider,
      });

      // Audit Log Ingestion Event
      callAuditService('log_event', {
        actor_id: actor.email,
        actor_role: actor.role,
        action: 'DATA_SOURCE_INGEST',
        target_type: 'ENTERPRISE_TELEMETRY',
        target_id: queueRes[1] || ingestResult.signature,
        result: queueRes[0] ? 'SUCCESS' : 'FAILURE',
        tenant_id: actor.tenant_id,
        details: {
          provider,
          event_type: ingestResult.normalized_event?.attack_category,
          severity: ingestResult.normalized_event?.severity,
          is_verified: ingestResult.is_verified_provider,
        },
      });

      if (!queueRes[0] && queueRes[1] === 'QUEUE_FULL') {
        return res.status(429).json({
          error: 'Ingestion queue backpressure capacity reached. Telemetry throttled.',
          code: 'QUEUE_BACKPRESSURE',
        });
      }

      return res.json({
        success: true,
        status: 'ENQUEUED',
        queue_item_id: queueRes[1],
        normalized_event: ingestResult.normalized_event,
        is_verified_provider: ingestResult.is_verified_provider,
      });
    } catch (err: any) {
      return res.status(500).json({ error: 'Enterprise ingestion failed', details: err.message });
    }
  });

  app.post('/api/integrations/test/:provider', (req, res) => {
    try {
      const provider = req.params.provider;
      const rawData = req.body;
      const result = callIntegrationHub('ingest_payload', { provider_key: provider, raw_data: rawData });
      return res.json(result);
    } catch (err: any) {
      return res.status(400).json({ error: 'Adapter test failed', details: err.message });
    }
  });

  // =========================================================================
  // Scalable Ingestion Pipeline & Event Queue Endpoints
  // =========================================================================

  app.get('/api/pipeline/queue-status', (req, res) => {
    try {
      const status = callEventQueue('get_status');
      return res.json(status);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to retrieve queue status', details: err.message });
    }
  });

  app.get('/api/pipeline/dlq', requireRole(['ADMIN', 'SECURITY_ADMIN', 'SECURITY_ANALYST']), (req, res) => {
    try {
      const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
      const dlqItems = callEventQueue('list_dlq', { limit });
      return res.json(dlqItems);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to retrieve DLQ', details: err.message });
    }
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.nvd_sync_service import sync_nvd; print(json.dumps(sync_nvd(resultsPerPage=${parseInt(resultsPerPage, 10)}, startIndex=${parseInt(startIndex, 10)}${keyword ? `, keyword='${keyword.replace(/'/g, "\\'")}'` : ''}${cve_id ? `, cve_id='${cve_id.replace(/'/g, "\\'")}'` : ''})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.nvd_sync_service import get_nvd_sync_status; print(json.dumps(get_nvd_sync_status()))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.nvd_sync_service import get_vulnerabilities; print(json.dumps(get_vulnerabilities(limit=${parseInt(String(limit), 10)}, offset=${parseInt(String(offset), 10)}, severity='${String(severity)}')))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.cisa_kev_sync_service import sync_cisa_kev; print(json.dumps(sync_cisa_kev(${limit ? `limit=${parseInt(limit, 10)}` : ''})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.cisa_kev_sync_service import get_cisa_kev_sync_status; print(json.dumps(get_cisa_kev_sync_status()))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.cisa_kev_sync_service import get_known_exploited_vulnerabilities; print(json.dumps(get_known_exploited_vulnerabilities(limit=${parseInt(String(limit), 10)}, offset=${parseInt(String(offset), 10)}${vendor ? `, vendor='${String(vendor).replace(/'/g, "\\'")}'` : ''}${product ? `, product='${String(product).replace(/'/g, "\\'")}'` : ''}${search ? `, search='${String(search).replace(/'/g, "\\'")}'` : ''})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.providers.security_dataset_provider import SecurityDatasetProvider; print(json.dumps(SecurityDatasetProvider().get_dataset_info()))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.security_event_service import import_dataset_into_db; print(json.dumps(import_dataset_into_db(${dataset_path ? `dataset_path='${dataset_path.replace(/'/g, "\\'")}', ` : ''}${limit ? `limit=${parseInt(limit, 10)}, ` : ''}${chunk_size ? `chunk_size=${parseInt(chunk_size, 10)}` : ''})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.security_event_service import get_attacks_by_category, get_attacks_by_severity, get_top_source_ips, get_top_destination_ports, get_protocol_distribution, get_source_distribution, get_attacks_over_time; print(json.dumps({'by_category': get_attacks_by_category(), 'by_severity': get_attacks_by_severity(), 'top_source_ips': get_top_source_ips(limit=10), 'top_dest_ports': get_top_destination_ports(limit=10), 'protocols': get_protocol_distribution(), 'sources': get_source_distribution(), 'over_time': get_attacks_over_time(limit=15)}))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.security_event_service import get_security_events_filtered; print(json.dumps(get_security_events_filtered(dataset_source=${dataset_source && dataset_source !== 'ALL' ? `'${String(dataset_source).replace(/'/g, "\\'")}'` : 'None'}, attack_category=${category && category !== 'ALL' ? `'${String(category).replace(/'/g, "\\'")}'` : 'None'}, severity=${severity && severity !== 'ALL' ? `'${String(severity).replace(/'/g, "\\'")}'` : 'None'}, protocol=${protocol && protocol !== 'ALL' ? `'${String(protocol).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)}, offset=${parseInt(String(offset), 10)})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.correlation_engine import run_correlation; print(json.dumps(run_correlation()))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.correlation_engine import SecurityCorrelationEngine; print(json.dumps(SecurityCorrelationEngine().get_findings(risk_level=${risk_level && risk_level !== 'ALL' ? `'${String(risk_level).replace(/'/g, "\\'")}'` : 'None'}, asset_id=${asset_id && asset_id !== 'ALL' ? `'${String(asset_id).replace(/'/g, "\\'")}'` : 'None'}, cve_id=${cve_id && cve_id !== 'ALL' ? `'${String(cve_id).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.correlation_engine import SecurityCorrelationEngine; engine = SecurityCorrelationEngine(); print(json.dumps({'top_risks': engine.get_top_correlated_risks(5), 'top_assets': engine.get_top_affected_assets(5), 'top_vulnerabilities': engine.get_top_vulnerabilities_with_events(5)}))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.risk_engine import get_risk_history; print(json.dumps(get_risk_history(asset=${asset && asset !== 'ALL' ? `'${String(asset).replace(/'/g, "\\'")}'` : 'None'}, finding=${finding && finding !== 'ALL' ? `'${String(finding).replace(/'/g, "\\'")}'` : 'None'}, level=${level && level !== 'ALL' ? `'${String(level).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.risk_engine import get_risk_over_time_trend; print(json.dumps(get_risk_over_time_trend(asset=${asset && asset !== 'ALL' ? `'${String(asset).replace(/'/g, "\\'")}'` : 'None'}, limit=${parseInt(String(limit), 10)})))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.risk_engine import calculate_final_risk; data = json.load(sys.stdin); print(json.dumps(calculate_final_risk(**data)))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.event_simulator import get_simulator; print(json.dumps(get_simulator().generate_event()))"`;
      execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
    } catch (e) {
      console.error('Simulation tick error:', e);
    }
  }

  // Live Monitoring Metrics Endpoint
  app.get('/api/simulator/live-stats', (req, res) => {
    try {
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.event_simulator import get_simulator; print(json.dumps(get_simulator().get_live_monitoring_stats()))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.event_simulator import get_simulator; data = json.load(sys.stdin); etype = data.get('type'); print(json.dumps(get_simulator().generate_event(etype)))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.rag.indexer import get_index_stats; print(json.dumps(get_index_stats()))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.rag.retriever import retrieve; d = json.load(sys.stdin); q = d.get('query', ''); c = d.get('collection'); n = int(d.get('n_results', 5)); f = d.get('filters') or d.get('where'); res = retrieve(q, filters=f, n_results=n, collection=c); print(json.dumps(res if isinstance(res, (list, dict)) else {'message': res, 'results': []}))"`;
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
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.rag.indexer import index_all, index_vulnerabilities, index_kev, index_nist, index_findings, index_assets, index_incidents; d = json.load(sys.stdin); domain = d.get('domain', 'all'); limit = d.get('limit'); res = index_vulnerabilities(limit=limit) if domain == 'vulnerabilities' else (index_kev(limit=limit) if domain == 'kev' else (index_nist() if domain == 'nist' else (index_findings(limit=limit) if domain == 'findings' else (index_assets() if domain == 'assets' else index_all(vuln_limit=limit, kev_limit=limit, incident_limit=limit))))); print(json.dumps(res))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 60000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'Indexing failed', details: err.message });
    }
  });

  // =========================================================================
  // CRISP Agent Swarm 2.0 Endpoints (LangGraph Supervised Architecture)
  // =========================================================================

  // Swarm Status Endpoint
  app.get('/api/agents/status', (req, res) => {
    try {
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.agents import get_swarm_status; print(json.dumps(get_swarm_status()))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to get agent swarm status', details: err.message });
    }
  });

  const AUTHORIZED_ROLES = new Set(['ADMIN', 'SECURITY_ANALYST', 'SOC_ANALYST', 'SECURITY_ADMIN', 'AUDITOR', 'CISO', 'READONLY_ANALYST']);

  // Swarm Investigation Endpoint
  app.post('/api/agents/investigate', (req, res) => {
    try {
      const userRole = (req.body?.user_role || 'SOC_ANALYST').toUpperCase();
      if (!AUTHORIZED_ROLES.has(userRole) || userRole === 'VIEWER') {
        return res.status(403).json({ error: `Unauthorized: user role '${userRole}' has insufficient permissions to perform multi-agent investigations.` });
      }
      const payload = JSON.stringify(req.body || {});

      // Audit log investigation initiation
      try {
        callAuditService('log_event', {
          actor_id: req.body?.user_email || 'saifkar98k@gmail.com',
          actor_role: userRole,
          action: 'INVESTIGATION_START',
          target_type: 'SWARM_INVESTIGATION',
          target_id: req.body?.target_cve || req.body?.target_asset || 'GENERAL_QUERY',
          result: 'SUCCESS',
          details: { query: (req.body?.query || '').substring(0, 100), targets: { cve: req.body?.target_cve, asset: req.body?.target_asset } },
        });
      } catch (e) {}

      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.agents import run_investigation; d = json.load(sys.stdin); print(json.dumps(run_investigation(query=d.get('query', ''), target_cve=d.get('target_cve'), target_asset=d.get('target_asset'), user_role=d.get('user_role', 'SOC_ANALYST'))))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 35000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'Agent investigation failed', details: err.message });
    }
  });

  // Swarm Investigation History Endpoint
  app.get('/api/agents/history', (req, res) => {
    try {
      const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
      const pyCmd = `${PYTHON_BIN} -c "import json; from services.agents import get_investigation_history; print(json.dumps(get_investigation_history(limit=${limit})))"`;
      const stdout = execSync(pyCmd, { encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to retrieve investigation history', details: err.message });
    }
  });

  // Swarm Real-Time Investigation Streaming (Server-Sent Events)
  const handleInvestigationStream = (req: express.Request, res: express.Response) => {
    const body = req.method === 'POST' ? req.body : req.query;
    const { query, target_cve, target_asset, user_role = 'SOC_ANALYST', client_id } = body || {};

    const normalizedRole = String(user_role || 'SOC_ANALYST').toUpperCase();
    if (!AUTHORIZED_ROLES.has(normalizedRole)) {
      return res.status(403).json({ error: `Unauthorized: user role '${normalizedRole}' has insufficient permissions to perform multi-agent investigations.` });
    }

    if (!query || typeof query !== 'string' || !query.trim()) {
      return res.status(400).json({ error: 'Investigation query is required' });
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    const processKey = client_id || `proc_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const child = spawn(PYTHON_BIN, ['-u', '-m', 'services.agents.stream_runner'], {
      cwd: __dirname,
      env: { ...process.env, PYTHONPATH: __dirname, PYTHONUNBUFFERED: '1' },
    });
    activeProcesses.set(processKey, child);


    let stdoutBuffer = '';

    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBuffer += chunk.toString();
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop() || '';
      for (const line of lines) {
        if (line.trim()) {
          res.write(`data: ${line.trim()}\n\n`);
        }
      }
    });

    child.stderr.on('data', (errChunk: Buffer) => {
      console.warn('Agent stream stderr:', errChunk.toString());
    });

    let isFinished = false;
    child.on('close', (code: number | null) => {
      isFinished = true;
      activeProcesses.delete(processKey);
      if (stdoutBuffer.trim()) {
        res.write(`data: ${stdoutBuffer.trim()}\n\n`);
      }
      res.write(`data: ${JSON.stringify({ type: 'stream_end', exitCode: code })}\n\n`);
      res.end();
    });

    child.on('error', (err: Error) => {
      isFinished = true;
      activeProcesses.delete(processKey);
      res.write(`data: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`);
      res.end();
    });

    res.on('close', () => {
      if (!isFinished && !child.killed) {
        try {
          child.kill('SIGTERM');
        } catch (e) {}
      }
      activeProcesses.delete(processKey);
    });

    // Write input payload to stdin
    const inputPayload = JSON.stringify({
      query: query.trim(),
      target_cve: target_cve || null,
      target_asset: target_asset || null,
      user_role,
    });
    child.stdin.write(inputPayload);
    child.stdin.end();
  };


  app.post('/api/agents/investigate/stream', handleInvestigationStream);
  app.get('/api/agents/investigate/stream', handleInvestigationStream);

  // Swarm Investigation Cancellation Endpoint
  app.post('/api/agents/cancel', (req, res) => {
    const { client_id, process_key } = req.body || {};
    const key = client_id || process_key;
    if (key && activeProcesses.has(key)) {
      const proc = activeProcesses.get(key);
      try {
        proc.kill('SIGTERM');
        activeProcesses.delete(key);
        return res.json({ status: 'cancelled', message: `Investigation ${key} aborted.` });
      } catch (err: any) {
        return res.status(500).json({ error: 'Failed to cancel investigation', details: err.message });
      }
    }
    // Cancel any active child processes
    let cancelledCount = 0;
    for (const [k, p] of activeProcesses.entries()) {
      try {
        p.kill('SIGTERM');
        activeProcesses.delete(k);
        cancelledCount++;
      } catch (e) {}
    }
    return res.json({
      status: 'cancelled',
      message: `Aborted ${cancelledCount} active investigation process(es).`,
    });
  });

  // Classic AI Security Assistant Fallback Endpoint (RAG + Groq)
  app.post('/api/agents/classic-assistant', (req, res) => {
    try {
      const payload = JSON.stringify(req.body || {});
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.rag.retriever import retrieve; from services.agents.groq_client import get_groq_client; d = json.load(sys.stdin); q = d.get('query', ''); hits = retrieve(q, n_results=4); hits_list = hits if isinstance(hits, list) else hits.get('results', []); groq = get_groq_client(); context_str = '\\n'.join([f'- {h.get(\\\"document\\\", \\\"\\\")[:200]}' for h in hits_list[:4]]); system_prompt = 'You are the CRISP AI Security Assistant. Answer accurately using only factual context provided.'; prompt = f'Context:\\n{context_str}\\n\\nQuestion: {q}'; answer = groq.generate(system_prompt=system_prompt, user_prompt=prompt, temperature=0.1); print(json.dumps({'answer': answer, 'sources': hits_list, 'model': groq.model, 'is_configured': groq.is_configured()}))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 25000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      return res.json(JSON.parse(lastLine));
    } catch (err: any) {
      return res.status(500).json({ error: 'Classic assistant query failed', details: err.message });
    }
  });

  // Swarm Specific Investigation Details
  app.get('/api/agents/history/:id', (req, res) => {
    try {
      const investigationId = req.params.id;
      const payload = JSON.stringify({ id: investigationId });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.agents import get_investigation_by_id; d = json.load(sys.stdin); res = get_investigation_by_id(d.get('id', '')); print(json.dumps(res if res else {'error': 'Investigation not found'}))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const lastLine = lines[lines.length - 1];
      const result = JSON.parse(lastLine);
      if (result && result.error) {
        return res.status(404).json(result);
      }
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to retrieve investigation', details: err.message });
    }
  });


  // =========================================================================
  // CRISP Remediation Intelligence Engine Endpoints
  // =========================================================================

  // List all remediation plans with optional filters
  app.get('/api/remediations', (req, res) => {
    try {
      const { status, priority, assetId, cveId, search } = req.query;
      const payload = JSON.stringify({ status, priority, assetId, cveId, search });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.remediation_engine import remediation_engine; d = json.load(sys.stdin); print(json.dumps(remediation_engine.list_plans(status=d.get('status'), priority=d.get('priority'), asset_id=d.get('assetId'), cve_id=d.get('cveId'), search=d.get('search'))))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      return res.json(JSON.parse(lines[lines.length - 1]));
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to list remediation plans', details: err.message });
    }
  });

  // Get single remediation plan
  app.get('/api/remediations/:id', (req, res) => {
    try {
      const payload = JSON.stringify({ id: req.params.id });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.remediation_engine import remediation_engine; d = json.load(sys.stdin); p = remediation_engine.get_plan(d.get('id')); print(json.dumps(p if p else {'error': 'Remediation plan not found'}))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      const result = JSON.parse(lines[lines.length - 1]);
      if (result && result.error) return res.status(404).json(result);
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to retrieve plan', details: err.message });
    }
  });

  // Generate remediation plan from finding (or auto-generate for all findings)
  app.post('/api/remediations/generate', (req, res) => {
    try {
      const { finding_id, generate_all } = req.body || {};
      const userRole = req.headers['x-user-role'] || req.body?.user_role || 'SOC_ANALYST';
      const userEmail = req.headers['x-user-email'] || req.body?.user_email || 'saifkar98k@gmail.com';

      const payload = JSON.stringify({ finding_id, generate_all, user_role: userRole, user_email: userEmail });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.remediation_engine import remediation_engine; d = json.load(sys.stdin); res = remediation_engine.generate_plans_for_all_findings() if d.get('generate_all') or not d.get('finding_id') else remediation_engine.create_plan_from_finding(d['finding_id'], assigned_to=d.get('user_email'), creator_role=d.get('user_role')); print(json.dumps(res))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 25000 });
      const lines = stdout.trim().split('\n');
      return res.json(JSON.parse(lines[lines.length - 1]));
    } catch (err: any) {
      return res.status(400).json({ error: 'Failed to generate remediation plan', details: err.message });
    }
  });

  // Update status with role authorization enforcement
  app.patch('/api/remediations/:id/status', (req, res) => {
    try {
      const remediationId = req.params.id;
      const { status, notes } = req.body || {};
      const userRole = String(req.headers['x-user-role'] || req.body?.user_role || 'SOC_ANALYST');
      const userEmail = String(req.headers['x-user-email'] || req.body?.user_email || 'saifkar98k@gmail.com');

      if (!status) {
        return res.status(400).json({ error: 'New status is required.' });
      }

      const payload = JSON.stringify({ remediation_id: remediationId, status, notes, user_role: userRole, user_id: userEmail });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.remediation_engine import remediation_engine; d = json.load(sys.stdin); res = remediation_engine.update_status(d['remediation_id'], d['status'], user_role=d.get('user_role'), user_id=d.get('user_id'), notes=d.get('notes', '')); print(json.dumps(res))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      return res.json(JSON.parse(lines[lines.length - 1]));
    } catch (err: any) {
      return res.status(403).json({ error: 'Status update failed', details: err.message });
    }
  });

  // Submit verification evidence and recalculate risk
  app.post('/api/remediations/:id/verify', (req, res) => {
    try {
      const remediationId = req.params.id;
      const { evidence, notes } = req.body || {};
      const userRole = String(req.headers['x-user-role'] || req.body?.user_role || 'SOC_ANALYST');
      const userEmail = String(req.headers['x-user-email'] || req.body?.user_email || 'saifkar98k@gmail.com');

      if (!evidence || typeof evidence !== 'object') {
        return res.status(400).json({ error: 'Substantive verification evidence object is required.' });
      }

      const payload = JSON.stringify({ remediation_id: remediationId, evidence, notes, user_role: userRole, user_id: userEmail });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.remediation_engine import remediation_engine; d = json.load(sys.stdin); res = remediation_engine.submit_verification(d['remediation_id'], d['evidence'], user_role=d.get('user_role'), user_id=d.get('user_id'), notes=d.get('notes', '')); print(json.dumps(res))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 20000 });
      const lines = stdout.trim().split('\n');
      return res.json(JSON.parse(lines[lines.length - 1]));
    } catch (err: any) {
      return res.status(400).json({ error: 'Verification failed', details: err.message });
    }
  });

  // Explicitly reopen remediation plan
  app.post('/api/remediations/:id/reopen', (req, res) => {
    try {
      const remediationId = req.params.id;
      const { reason } = req.body || {};
      const userRole = String(req.headers['x-user-role'] || req.body?.user_role || 'SOC_ANALYST');
      const userEmail = String(req.headers['x-user-email'] || req.body?.user_email || 'saifkar98k@gmail.com');

      if (!reason) {
        return res.status(400).json({ error: 'Reopening reason is required.' });
      }

      const payload = JSON.stringify({ remediation_id: remediationId, reason, user_role: userRole, user_id: userEmail });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.remediation_engine import remediation_engine; d = json.load(sys.stdin); res = remediation_engine.reopen_plan(d['remediation_id'], d['reason'], user_role=d.get('user_role'), user_id=d.get('user_id')); print(json.dumps(res))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 15000 });
      const lines = stdout.trim().split('\n');
      return res.json(JSON.parse(lines[lines.length - 1]));
    } catch (err: any) {
      return res.status(400).json({ error: 'Failed to reopen plan', details: err.message });
    }
  });

  // AI Remediation Assistant
  app.post('/api/remediations/:id/ai-assist', (req, res) => {
    try {
      const remediationId = req.params.id;
      const { question } = req.body || {};
      const payload = JSON.stringify({ remediation_id: remediationId, question });
      const pyCmd = `${PYTHON_BIN} -c "import sys, json; from services.remediation_engine import remediation_engine; from services.agents.groq_client import get_groq_client; from services.rag.retriever import retrieve; d = json.load(sys.stdin); p = remediation_engine.get_plan(d.get('remediation_id')); q = d.get('question') or ''; plan_ctx = json.dumps(p, indent=2) if p else 'Plan not found'; rag_hits = retrieve(f\\\"{p.get('cve_id', '')} remediation {p.get('asset_name', '')}\\\", n_results=3); rag_ctx = '\\n'.join([h.get('document', '')[:200] for h in rag_hits]) if isinstance(rag_hits, list) else ''; groq = get_groq_client(); sys_prompt = 'You are the CRISP AI Remediation Assistant. Analyze the remediation plan with strict factual accuracy. Explain why the remediation is recommended, distinguish verified facts from proposed actions, cite evidence and vendor source references, explain operational urgency and potential blast radius, identify missing information, and ask for clarification when asset or product version is ambiguous. NEVER invent fake commands or false versions.'; user_prompt = f'Plan Context:\\n{plan_ctx}\\n\\nRAG Knowledge:\\n{rag_ctx}\\n\\nAnalyst Query: {q or \\\"Generate a comprehensive technical remediation briefing, blast radius analysis, and verification plan.\\\"}'; answer = groq.generate(system_prompt=sys_prompt, user_prompt=user_prompt, temperature=0.1); print(json.dumps({'plan_id': d.get('remediation_id'), 'analysis': answer, 'model': groq.model, 'is_configured': groq.is_configured()}))"`;
      const stdout = execSync(pyCmd, { input: payload, encoding: 'utf-8', timeout: 35000 });
      const lines = stdout.trim().split('\n');
      return res.json(JSON.parse(lines[lines.length - 1]));
    } catch (err: any) {
      return res.status(500).json({ error: 'AI remediation assistant failed', details: err.message });
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
