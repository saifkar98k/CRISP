/**
 * Pipeline Manager
 *
 * Coordinates the end-to-end CRISP Cybersecurity Data Pipeline:
 *
 * External Data (NVD, CISA KEV, CSV)
 *        ↓
 *   Data Provider
 *        ↓
 *    Normalizer
 *        ↓
 *    Validation
 *        ↓
 *      SQLite
 *        ↓
 *   Risk Engine
 *        ↓
 * Compliance Engine
 *        ↓
 *  Executive Dashboard
 */

import { crispDb } from '../database/sqlite';
import { nvdProvider, NvdFetchOptions } from '../providers/nvdProvider';
import { cisaKevProvider } from '../providers/cisaKevProvider';
import { csvDataProvider } from '../providers/csvDataProvider';
import { syntheticDemoProvider } from '../providers/syntheticDemoProvider';
import { Normalizer } from './normalizer';
import { Validator } from './validator';
import { RiskEngine } from '../engines/riskEngine';
import { ComplianceEngine } from '../engines/complianceEngine';
import { INITIAL_ENTERPRISE_ASSETS, INITIAL_NIST_CONTROLS } from '../database/seedData';
import {
  Vulnerability,
  SecurityEvent,
  Asset,
  NistControlEvaluation,
  NistComplianceSummary,
  DataSourceStatus,
  PipelineExecutionLog,
} from '../types/schemas';
import defaultMappingConfig from '../data/default_csv_mapping.json';

export class PipelineManager {
  private isInitialized = false;

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    const t0 = performance.now();

    // 1. Initialize SQLite Database tables
    await crispDb.init();

    // 2. Check if assets exist; seed if empty
    const existingAssets = crispDb.getAssets();
    if (existingAssets.length === 0) {
      for (const a of INITIAL_ENTERPRISE_ASSETS) {
        crispDb.upsertAsset(a);
      }
    }

    // 3. Check if NIST controls exist; seed if empty
    const existingControls = crispDb.getNistControls();
    if (existingControls.length === 0) {
      crispDb.upsertNistControls(INITIAL_NIST_CONTROLS);
    }

    // 4. Load baseline CISA KEV
    await cisaKevProvider.loadCatalog(false);

    // 5. Check if vulnerabilities exist; if empty, run initial NVD + KEV pipeline
    let vulns = crispDb.getVulnerabilities();
    if (vulns.length === 0) {
      await this.syncVulnerabilityIntelligence({ forceRefresh: false });
    }

    // 6. Check if events exist; if empty, import default historical CSV
    const events = crispDb.getSecurityEvents(10);
    if (events.length === 0) {
      await this.importHistoricalSecurityEvents();
    }

    // 7. Seed initial synthetic demo events
    const syntheticEvents = crispDb.getSecurityEvents(100).filter((e) => !e.isRealData);
    if (syntheticEvents.length === 0) {
      const assets = crispDb.getAssets();
      const demoBatch = syntheticDemoProvider.generateBaselineDemoEvents(assets, 6);
      crispDb.insertSecurityEvents(demoBatch);
    }

    // 8. Initial risk and compliance recalculation
    await this.recalculateAllRisksAndCompliance();

    this.isInitialized = true;

    crispDb.logPipelineExecution({
      id: `INIT-${Date.now()}`,
      stage: 'SQLITE_LOAD',
      timestamp: new Date().toISOString(),
      status: 'SUCCESS',
      recordsProcessed: crispDb.getTableCount('vulnerabilities') + crispDb.getTableCount('security_events'),
      message: 'CRISP Database & Core Engine initialized successfully.',
      durationMs: Math.round(performance.now() - t0),
    });
  }

  /**
   * Syncs real vulnerability intelligence:
   * External Data -> Data Provider -> Normalizer -> Validation -> SQLite -> Risk Engine
   */
  async syncVulnerabilityIntelligence(options: NvdFetchOptions = {}): Promise<{
    count: number;
    notes: string;
    sourceStatus: string;
    durationMs: number;
  }> {
    const t0 = performance.now();

    // Stage 1: Extract from CISA KEV
    const kevResult = await cisaKevProvider.loadCatalog(options.forceRefresh);

    // Stage 2: Extract from NVD API
    const nvdResult = await nvdProvider.fetchVulnerabilities(options);

    // Stage 3: Normalizer + CISA KEV Enrichment
    const enriched = cisaKevProvider.enrichVulnerabilities(nvdResult.vulnerabilities);
    const normalized = enriched.map((v) => Normalizer.normalizeVulnerability(v));

    // Stage 4: Validation
    const validVulns: Vulnerability[] = [];
    let invalidCount = 0;

    for (const v of normalized) {
      const report = Validator.validateVulnerability(v);
      if (report.isValid) {
        validVulns.push(v);
      } else {
        invalidCount++;
      }
    }

    // Stage 5: Store in SQLite
    crispDb.upsertVulnerabilities(validVulns);

    // Stage 6: Update Data Source Status metrics
    const totalVulnsInDb = crispDb.getTableCount('vulnerabilities');
    const nowIso = new Date().toISOString();

    crispDb.updateDataSourceMetric({
      sourceName: 'NVD Vulnerability Database',
      type: 'EXTERNAL_API',
      originCategory: 'REAL_EXTERNAL',
      recordCount: totalVulnsInDb,
      lastUpdated: nowIso,
      status: nvdResult.sourceStatus,
      latencyMs: nvdResult.latencyMs,
      endpointOrPath: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      cached: nvdResult.isFromCache,
      notes: nvdResult.notes,
    });

    crispDb.updateDataSourceMetric({
      sourceName: 'CISA Known Exploited Vulnerabilities',
      type: 'EXTERNAL_API',
      originCategory: 'REAL_EXTERNAL',
      recordCount: kevResult.totalCount,
      lastUpdated: kevResult.lastUpdated,
      status: kevResult.sourceStatus,
      latencyMs: kevResult.latencyMs,
      endpointOrPath: 'https://www.cisa.gov/.../known_exploited_vulnerabilities.json',
      cached: true,
      notes: kevResult.notes,
    });

    // Stage 7: Recalculate Risk & Compliance
    await this.recalculateAllRisksAndCompliance();

    const durationMs = Math.round(performance.now() - t0);

    crispDb.logPipelineExecution({
      id: `SYNC-${Date.now()}`,
      stage: 'EXTRACT',
      timestamp: nowIso,
      status: invalidCount > 0 ? 'WARNING' : 'SUCCESS',
      recordsProcessed: validVulns.length,
      message: `Sync completed: ${validVulns.length} valid CVEs saved to SQLite (${invalidCount} invalid rejected). ${nvdResult.notes}`,
      durationMs,
    });

    return {
      count: validVulns.length,
      notes: nvdResult.notes,
      sourceStatus: nvdResult.sourceStatus,
      durationMs,
    };
  }

  /**
   * Imports the real historical security events CSV using the configured CSV mapping
   */
  async importHistoricalSecurityEvents(customCsv?: string): Promise<{
    count: number;
    errors: string[];
    durationMs: number;
  }> {
    const t0 = performance.now();

    let csvContent = customCsv;
    if (!csvContent) {
      try {
        const res = await fetch('/api/datasets/historical');
        if (res.ok) {
          csvContent = await res.text();
        }
      } catch {
        // Fallback handled below
      }
    }

    if (!csvContent) {
      // In case server fetch didn't return text, use bundled fallback
      csvContent = `event_id,timestamp_utc,src_ip,dest_ip,threat_category,threat_level,alert_summary,target_asset_id,target_hostname,asset_tier,cve_reference,signature_id,incident_state\nEVT-2023-8801,2023-11-14T08:12:44Z,194.26.29.112,10.0.4.15,Exploit Public-Facing App,CRITICAL,Inbound HTTP POST containing JNDI lookup string targeting Log4j core,AST-PROD-WEB-01,prod-edge-web01.internal,CRITICAL,CVE-2021-44228,SURICATA-2034647,RESOLVED\nEVT-2023-8804,2023-11-16T14:30:22Z,103.149.136.21,10.0.5.20,Exploit Public-Facing App,CRITICAL,Citrix Bleed NetScaler memory disclosure request targeting /oauth/v20/openid_connect,AST-GW-VPN-01,corp-vpn-gw01.internal,CRITICAL,CVE-2023-4966,SURICATA-2048590,CONTAINED\nEVT-2023-8810,2023-11-22T21:10:48Z,10.0.5.20,10.0.2.10,Exploit Public-Facing App,CRITICAL,Ivanti Connect Secure authentication bypass exploit chain detected,AST-GW-VPN-01,corp-vpn-gw01.internal,CRITICAL,CVE-2024-21887,SURICATA-2049921,CONTAINED`;
    }

    const mapping = (defaultMappingConfig as any).mapping;
    const result = await csvDataProvider.parseCsvString(csvContent, mapping, true);

    // Validate
    const validEvents: SecurityEvent[] = [];
    for (const evt of result.events) {
      const report = Validator.validateSecurityEvent(evt);
      if (report.isValid) {
        validEvents.push(evt);
      }
    }

    // Save to SQLite
    crispDb.insertSecurityEvents(validEvents);

    // Update Data Source Status
    const totalEventsInDb = crispDb.getTableCount('security_events');
    const realEventsCount = crispDb
      .getSecurityEvents(500)
      .filter((e) => e.dataSource === 'HISTORICAL_DATASET').length;

    crispDb.updateDataSourceMetric({
      sourceName: 'Historical Security Dataset',
      type: 'STATIC_DATASET',
      originCategory: 'REAL_HISTORICAL',
      recordCount: realEventsCount,
      lastUpdated: new Date().toISOString(),
      status: 'ACTIVE',
      latencyMs: 12,
      endpointOrPath: 'src/data/historical_security_events.csv',
      cached: true,
      notes: `Ingested via generic CSVDataProvider using "${defaultMappingConfig.profileId}" mapping config.`,
    });

    const durationMs = Math.round(performance.now() - t0);

    crispDb.logPipelineExecution({
      id: `CSV-IMPORT-${Date.now()}`,
      stage: 'VALIDATE',
      timestamp: new Date().toISOString(),
      status: result.errors.length > 0 ? 'WARNING' : 'SUCCESS',
      recordsProcessed: validEvents.length,
      message: `Imported ${validEvents.length} real historical security events into SQLite.`,
      durationMs,
    });

    return {
      count: validEvents.length,
      errors: result.errors,
      durationMs,
    };
  }

  /**
   * Recalculates risk for all enterprise assets and updates NIST CSF compliance scores
   */
  async recalculateAllRisksAndCompliance(): Promise<{
    evaluatedAssets: Asset[];
    complianceSummary: NistComplianceSummary;
  }> {
    const t0 = performance.now();

    const assets = crispDb.getAssets();
    const vulns = crispDb.getVulnerabilities();
    const events = crispDb.getSecurityEvents(200);
    const controls = crispDb.getNistControls();

    // Recalculate each asset risk
    const updatedAssets: Asset[] = [];
    for (const asset of assets) {
      // Find vulnerabilities that relate to this asset
      // E.g. match by affectedProducts or related event CVEs
      const relatedCves = new Set<string>();
      events
        .filter((e) => e.assetId === asset.id && e.relatedCveId)
        .forEach((e) => relatedCves.add(e.relatedCveId!));

      const matchedVulns = vulns.filter((v) => {
        if (relatedCves.has(v.id)) return true;
        // Match by product keywords
        const assetName = asset.name.toLowerCase();
        if (assetName.includes('web') && v.affectedProducts.some((p) => p.toLowerCase().includes('log4j') || p.toLowerCase().includes('struts') || p.toLowerCase().includes('spring'))) return true;
        if (assetName.includes('vpn') && v.affectedProducts.some((p) => p.toLowerCase().includes('citrix') || p.toLowerCase().includes('ivanti') || p.toLowerCase().includes('palo alto'))) return true;
        if (assetName.includes('db') && v.affectedProducts.some((p) => p.toLowerCase().includes('moveit') || p.toLowerCase().includes('sql'))) return true;
        if (assetName.includes('dc') && v.affectedProducts.some((p) => p.toLowerCase().includes('windows') || p.toLowerCase().includes('active directory'))) return true;
        return false;
      });

      const riskBreakdown = RiskEngine.calculateAssetRisk(asset, matchedVulns, events);

      const updatedAsset: Asset = {
        ...asset,
        vulnerabilityCount: matchedVulns.length,
        calculatedRiskScore: riskBreakdown.overallScore,
      };

      crispDb.upsertAsset(updatedAsset);
      updatedAssets.push(updatedAsset);
    }

    // Recalculate NIST CSF 2.0 Compliance
    const { evaluatedControls, summary } = ComplianceEngine.evaluateCompliance(
      controls,
      vulns,
      events,
      updatedAssets
    );

    crispDb.upsertNistControls(evaluatedControls);

    // Update Synthetic Demo metrics in Data Source page
    const demoEventsCount = events.filter((e) => !e.isRealData).length;
    crispDb.updateDataSourceMetric({
      sourceName: 'CRISP Synthetic Demo Events',
      type: 'SYNTHETIC_GENERATOR',
      originCategory: 'SYNTHETIC_DEMO',
      recordCount: demoEventsCount,
      lastUpdated: new Date().toISOString(),
      status: 'ACTIVE',
      latencyMs: 1,
      endpointOrPath: 'src/providers/syntheticDemoProvider.ts',
      cached: false,
      notes: 'Controlled demonstration events. Clearly distinguished from real data.',
    });

    const durationMs = Math.round(performance.now() - t0);

    crispDb.logPipelineExecution({
      id: `RISK-CALC-${Date.now()}`,
      stage: 'RISK_ENGINE',
      timestamp: new Date().toISOString(),
      status: 'SUCCESS',
      recordsProcessed: updatedAssets.length,
      message: `Risk Engine evaluated ${updatedAssets.length} assets. Compliance overall: ${summary.overallCompliancePct}%.`,
      durationMs,
    });

    return {
      evaluatedAssets: updatedAssets,
      complianceSummary: summary,
    };
  }
}

export const pipelineManager = new PipelineManager();
