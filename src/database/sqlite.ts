/**
 * CRISP SQLite Database Manager (WebAssembly SQLite via sql.js)
 *
 * Implements real local embedded SQLite storage for:
 * - Real NVD vulnerabilities
 * - CISA KEV catalog records
 * - Historical cybersecurity events
 * - Synthetic live demo events
 * - Enterprise assets & risk assessments
 * - NIST CSF 2.0 controls & evaluations
 */

import initSqlJs, { Database, SqlJsStatic } from 'sql.js';
import {
  Vulnerability,
  SecurityEvent,
  Asset,
  NistControlEvaluation,
  DataSourceStatus,
  PipelineExecutionLog
} from '../types/schemas';

let sqlPromise: Promise<SqlJsStatic> | null = null;

function getSqlJs(): Promise<SqlJsStatic> {
  if (!sqlPromise) {
    sqlPromise = initSqlJs({
      locateFile: () => '/sql-wasm.wasm',
    });
  }
  return sqlPromise;
}

export class CrispDatabase {
  private db: Database | null = null;
  private isInitialized = false;

  async init(): Promise<void> {
    if (this.isInitialized && this.db) return;

    const SQL = await getSqlJs();
    this.db = new SQL.Database();
    this.createTables();
    this.isInitialized = true;
  }

  private createTables(): void {
    if (!this.db) return;

    this.db.run(`
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        cvss_score REAL DEFAULT 0.0,
        cvss_vector TEXT,
        severity TEXT,
        affected_products TEXT,
        cwe TEXT,
        published_date TEXT,
        modified_date TEXT,
        references_json TEXT,
        is_known_exploited INTEGER DEFAULT 0,
        kev_date_added TEXT,
        kev_vendor TEXT,
        kev_product TEXT,
        kev_vuln_name TEXT,
        kev_required_action TEXT,
        kev_due_date TEXT,
        data_source TEXT,
        is_real_data INTEGER DEFAULT 1,
        last_retrieved_at TEXT
      );

      CREATE TABLE IF NOT EXISTS security_events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        asset_id TEXT,
        asset_name TEXT,
        asset_criticality TEXT,
        attack_category TEXT,
        severity TEXT,
        description TEXT,
        related_cve_id TEXT,
        detection_rule TEXT,
        status TEXT,
        data_source TEXT,
        is_real_data INTEGER DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        ip_address TEXT,
        type TEXT,
        criticality TEXT,
        exposure TEXT,
        owner TEXT,
        department TEXT,
        vulnerability_count INTEGER DEFAULT 0,
        calculated_risk_score REAL DEFAULT 0.0
      );

      CREATE TABLE IF NOT EXISTS nist_controls (
        id TEXT PRIMARY KEY,
        category TEXT,
        subcategory TEXT,
        function TEXT,
        score REAL,
        status TEXT,
        findings TEXT,
        required_remediation TEXT,
        evidence TEXT
      );

      CREATE TABLE IF NOT EXISTS data_source_metrics (
        source_name TEXT PRIMARY KEY,
        type TEXT,
        origin_category TEXT,
        record_count INTEGER DEFAULT 0,
        last_updated TEXT,
        status TEXT,
        latency_ms INTEGER DEFAULT 0,
        endpoint_or_path TEXT,
        cached INTEGER DEFAULT 0,
        notes TEXT
      );

      CREATE TABLE IF NOT EXISTS pipeline_logs (
        id TEXT PRIMARY KEY,
        stage TEXT,
        timestamp TEXT,
        status TEXT,
        records_processed INTEGER,
        message TEXT,
        duration_ms REAL
      );
    `);
  }

  // --- Vulnerabilities Operations ---
  upsertVulnerability(vuln: Vulnerability): void {
    if (!this.db) return;

    const stmt = this.db.prepare(`
      INSERT INTO vulnerabilities (
        id, title, description, cvss_score, cvss_vector, severity,
        affected_products, cwe, published_date, modified_date,
        references_json, is_known_exploited, kev_date_added,
        kev_vendor, kev_product, kev_vuln_name, kev_required_action,
        kev_due_date, data_source, is_real_data, last_retrieved_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        title = excluded.title,
        description = excluded.description,
        cvss_score = excluded.cvss_score,
        cvss_vector = excluded.cvss_vector,
        severity = excluded.severity,
        affected_products = excluded.affected_products,
        cwe = excluded.cwe,
        modified_date = excluded.modified_date,
        is_known_exploited = CASE WHEN excluded.is_known_exploited = 1 THEN 1 ELSE vulnerabilities.is_known_exploited END,
        kev_date_added = COALESCE(excluded.kev_date_added, vulnerabilities.kev_date_added),
        kev_vendor = COALESCE(excluded.kev_vendor, vulnerabilities.kev_vendor),
        kev_product = COALESCE(excluded.kev_product, vulnerabilities.kev_product),
        kev_vuln_name = COALESCE(excluded.kev_vuln_name, vulnerabilities.kev_vuln_name),
        kev_required_action = COALESCE(excluded.kev_required_action, vulnerabilities.kev_required_action),
        kev_due_date = COALESCE(excluded.kev_due_date, vulnerabilities.kev_due_date),
        last_retrieved_at = excluded.last_retrieved_at;
    `);

    stmt.run([
      vuln.id,
      vuln.title,
      vuln.description,
      vuln.cvssScore,
      vuln.cvssVector || null,
      vuln.severity,
      JSON.stringify(vuln.affectedProducts || []),
      JSON.stringify(vuln.cwe || []),
      vuln.publishedDate,
      vuln.modifiedDate,
      JSON.stringify(vuln.references || []),
      vuln.isKnownExploited ? 1 : 0,
      vuln.kevDateAdded || null,
      vuln.kevVendorProject || null,
      vuln.kevProduct || null,
      vuln.kevVulnerabilityName || null,
      vuln.kevRequiredAction || null,
      vuln.kevDueDate || null,
      vuln.dataSource,
      vuln.isRealData ? 1 : 0,
      vuln.lastRetrievedAt,
    ]);
    stmt.free();
  }

  upsertVulnerabilities(vulns: Vulnerability[]): void {
    if (!this.db) return;
    this.db.run('BEGIN TRANSACTION;');
    try {
      for (const vuln of vulns) {
        this.upsertVulnerability(vuln);
      }
      this.db.run('COMMIT;');
    } catch (e) {
      this.db.run('ROLLBACK;');
      throw e;
    }
  }

  getVulnerabilities(): Vulnerability[] {
    if (!this.db) return [];
    const res = this.db.exec('SELECT * FROM vulnerabilities ORDER BY cvss_score DESC, published_date DESC');
    if (!res || res.length === 0) return [];
    
    const columns = res[0].columns;
    const values = res[0].values;

    return values.map((row) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, idx) => {
        obj[col] = row[idx];
      });

      return {
        id: String(obj.id),
        title: String(obj.title || ''),
        description: String(obj.description || ''),
        cvssScore: Number(obj.cvss_score || 0),
        cvssVector: obj.cvss_vector ? String(obj.cvss_vector) : undefined,
        severity: (obj.severity as Vulnerability['severity']) || 'MEDIUM',
        affectedProducts: safeJsonParse<string[]>(obj.affected_products as string, []),
        cwe: safeJsonParse<string[]>(obj.cwe as string, []),
        publishedDate: String(obj.published_date || ''),
        modifiedDate: String(obj.modified_date || ''),
        references: safeJsonParse<string[]>(obj.references_json as string, []),
        isKnownExploited: Number(obj.is_known_exploited) === 1,
        kevDateAdded: obj.kev_date_added ? String(obj.kev_date_added) : undefined,
        kevVendorProject: obj.kev_vendor ? String(obj.kev_vendor) : undefined,
        kevProduct: obj.kev_product ? String(obj.kev_product) : undefined,
        kevVulnerabilityName: obj.kev_vuln_name ? String(obj.kev_vuln_name) : undefined,
        kevRequiredAction: obj.kev_required_action ? String(obj.kev_required_action) : undefined,
        kevDueDate: obj.kev_due_date ? String(obj.kev_due_date) : undefined,
        dataSource: (obj.data_source as Vulnerability['dataSource']) || 'NVD_API',
        isRealData: Number(obj.is_real_data) === 1,
        lastRetrievedAt: String(obj.last_retrieved_at || new Date().toISOString()),
      };
    });
  }

  // --- Security Events Operations ---
  insertSecurityEvent(evt: SecurityEvent): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO security_events (
        id, timestamp, source_ip, destination_ip, asset_id, asset_name,
        asset_criticality, attack_category, severity, description,
        related_cve_id, detection_rule, status, data_source, is_real_data
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run([
      evt.id,
      evt.timestamp,
      evt.sourceIp || null,
      evt.destinationIp || null,
      evt.assetId || null,
      evt.assetName || null,
      evt.assetCriticality || null,
      evt.attackCategory,
      evt.severity,
      evt.description,
      evt.relatedCveId || null,
      evt.detectionRule || null,
      evt.status,
      evt.dataSource,
      evt.isRealData ? 1 : 0,
    ]);
    stmt.free();
  }

  insertSecurityEvents(events: SecurityEvent[]): void {
    if (!this.db) return;
    this.db.run('BEGIN TRANSACTION;');
    try {
      for (const evt of events) {
        this.insertSecurityEvent(evt);
      }
      this.db.run('COMMIT;');
    } catch (e) {
      this.db.run('ROLLBACK;');
      throw e;
    }
  }

  getSecurityEvents(limit = 100): SecurityEvent[] {
    if (!this.db) return [];
    const query = `SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ${limit}`;
    const res = this.db.exec(query);
    if (!res || res.length === 0) return [];

    const columns = res[0].columns;
    const values = res[0].values;

    return values.map((row) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, idx) => {
        obj[col] = row[idx];
      });

      return {
        id: String(obj.id),
        timestamp: String(obj.timestamp),
        sourceIp: String(obj.source_ip || ''),
        destinationIp: String(obj.destination_ip || ''),
        assetId: String(obj.asset_id || ''),
        assetName: String(obj.asset_name || ''),
        assetCriticality: (obj.asset_criticality as SecurityEvent['assetCriticality']) || 'MEDIUM',
        attackCategory: (obj.attack_category as SecurityEvent['attackCategory']) || 'Reconnaissance',
        severity: (obj.severity as SecurityEvent['severity']) || 'MEDIUM',
        description: String(obj.description || ''),
        relatedCveId: obj.related_cve_id ? String(obj.related_cve_id) : undefined,
        detectionRule: String(obj.detection_rule || 'ANOMALY_DETECTOR'),
        status: (obj.status as SecurityEvent['status']) || 'ACTIVE',
        dataSource: (obj.data_source as SecurityEvent['dataSource']) || 'HISTORICAL_DATASET',
        isRealData: Number(obj.is_real_data) === 1,
      };
    });
  }

  // --- Assets Operations ---
  upsertAsset(asset: Asset): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO assets (
        id, name, ip_address, type, criticality, exposure, owner,
        department, vulnerability_count, calculated_risk_score
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run([
      asset.id,
      asset.name,
      asset.ipAddress,
      asset.type,
      asset.criticality,
      asset.exposure,
      asset.owner,
      asset.department,
      asset.vulnerabilityCount,
      asset.calculatedRiskScore,
    ]);
    stmt.free();
  }

  getAssets(): Asset[] {
    if (!this.db) return [];
    const res = this.db.exec('SELECT * FROM assets ORDER BY calculated_risk_score DESC, criticality DESC');
    if (!res || res.length === 0) return [];

    const columns = res[0].columns;
    const values = res[0].values;

    return values.map((row) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, idx) => {
        obj[col] = row[idx];
      });

      return {
        id: String(obj.id),
        name: String(obj.name),
        ipAddress: String(obj.ip_address),
        type: obj.type as Asset['type'],
        criticality: obj.criticality as Asset['criticality'],
        exposure: obj.exposure as Asset['exposure'],
        owner: String(obj.owner),
        department: String(obj.department),
        vulnerabilityCount: Number(obj.vulnerability_count || 0),
        calculatedRiskScore: Number(obj.calculated_risk_score || 0),
      };
    });
  }

  // --- NIST Controls Operations ---
  upsertNistControls(controls: NistControlEvaluation[]): void {
    if (!this.db) return;
    this.db.run('BEGIN TRANSACTION;');
    try {
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO nist_controls (
          id, category, subcategory, function, score, status,
          findings, required_remediation, evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const ctrl of controls) {
        stmt.run([
          ctrl.id,
          ctrl.category,
          ctrl.subcategory,
          ctrl.function,
          ctrl.score,
          ctrl.status,
          ctrl.findings,
          ctrl.requiredRemediation || null,
          ctrl.evidence,
        ]);
      }
      stmt.free();
      this.db.run('COMMIT;');
    } catch (e) {
      this.db.run('ROLLBACK;');
      throw e;
    }
  }

  getNistControls(): NistControlEvaluation[] {
    if (!this.db) return [];
    const res = this.db.exec('SELECT * FROM nist_controls ORDER BY id ASC');
    if (!res || res.length === 0) return [];

    const columns = res[0].columns;
    const values = res[0].values;

    return values.map((row) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, idx) => {
        obj[col] = row[idx];
      });

      return {
        id: String(obj.id),
        category: String(obj.category),
        subcategory: String(obj.subcategory),
        function: obj.function as NistControlEvaluation['function'],
        score: Number(obj.score),
        status: obj.status as NistControlEvaluation['status'],
        findings: String(obj.findings),
        requiredRemediation: obj.required_remediation ? String(obj.required_remediation) : undefined,
        evidence: String(obj.evidence),
      };
    });
  }

  // --- Data Source Metrics Operations ---
  updateDataSourceMetric(metric: DataSourceStatus): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO data_source_metrics (
        source_name, type, origin_category, record_count, last_updated,
        status, latency_ms, endpoint_or_path, cached, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run([
      metric.sourceName,
      metric.type,
      metric.originCategory,
      metric.recordCount,
      metric.lastUpdated,
      metric.status,
      metric.latencyMs,
      metric.endpointOrPath,
      metric.cached ? 1 : 0,
      metric.notes,
    ]);
    stmt.free();
  }

  getDataSourceMetrics(): DataSourceStatus[] {
    if (!this.db) return [];
    const res = this.db.exec('SELECT * FROM data_source_metrics ORDER BY source_name ASC');
    if (!res || res.length === 0) return [];

    const columns = res[0].columns;
    const values = res[0].values;

    return values.map((row) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, idx) => {
        obj[col] = row[idx];
      });

      return {
        sourceName: String(obj.source_name),
        type: obj.type as DataSourceStatus['type'],
        originCategory: obj.origin_category as DataSourceStatus['originCategory'],
        recordCount: Number(obj.record_count),
        lastUpdated: String(obj.last_updated),
        status: obj.status as DataSourceStatus['status'],
        latencyMs: Number(obj.latency_ms),
        endpointOrPath: String(obj.endpoint_or_path),
        cached: Number(obj.cached) === 1,
        notes: String(obj.notes || ''),
      };
    });
  }

  // --- Pipeline Logs ---
  logPipelineExecution(log: PipelineExecutionLog): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT INTO pipeline_logs (
        id, stage, timestamp, status, records_processed, message, duration_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run([
      log.id,
      log.stage,
      log.timestamp,
      log.status,
      log.recordsProcessed,
      log.message,
      log.durationMs,
    ]);
    stmt.free();
  }

  getPipelineLogs(limit = 25): PipelineExecutionLog[] {
    if (!this.db) return [];
    const res = this.db.exec(`SELECT * FROM pipeline_logs ORDER BY timestamp DESC LIMIT ${limit}`);
    if (!res || res.length === 0) return [];

    const columns = res[0].columns;
    const values = res[0].values;

    return values.map((row) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, idx) => {
        obj[col] = row[idx];
      });

      return {
        id: String(obj.id),
        stage: obj.stage as PipelineExecutionLog['stage'],
        timestamp: String(obj.timestamp),
        status: obj.status as PipelineExecutionLog['status'],
        recordsProcessed: Number(obj.records_processed),
        message: String(obj.message),
        durationMs: Number(obj.duration_ms),
      };
    });
  }

  // --- Arbitrary SQL Query Execution (For Live Database Explorer) ---
  executeRawQuery(sql: string): { columns: string[]; rows: (string | number | null)[][] } {
    if (!this.db) return { columns: [], rows: [] };
    const res = this.db.exec(sql);
    if (!res || res.length === 0) return { columns: [], rows: [] };
    return {
      columns: res[0].columns,
      rows: res[0].values as (string | number | null)[][],
    };
  }

  // Count helper
  getTableCount(tableName: string): number {
    if (!this.db) return 0;
    try {
      const res = this.db.exec(`SELECT COUNT(*) as cnt FROM ${tableName}`);
      if (res && res.length > 0 && res[0].values.length > 0) {
        return Number(res[0].values[0][0]);
      }
    } catch {
      return 0;
    }
    return 0;
  }
}

function safeJsonParse<T>(jsonStr: string | null | undefined, fallback: T): T {
  if (!jsonStr) return fallback;
  try {
    return JSON.parse(jsonStr) as T;
  } catch {
    return fallback;
  }
}

export const crispDb = new CrispDatabase();
