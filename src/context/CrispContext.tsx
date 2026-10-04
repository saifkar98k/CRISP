/**
 * CRISP Central Context & State Management
 *
 * Coordinates pipeline execution, SQLite state, real-time event simulation,
 * and data filtering across the dashboard.
 */

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import {
  Vulnerability,
  SecurityEvent,
  Asset,
  NistControlEvaluation,
  NistComplianceSummary,
  DataSourceStatus,
  PipelineExecutionLog,
} from '../types/schemas';
import { pipelineManager } from '../pipeline/pipelineManager';
import { crispDb } from '../database/sqlite';
import { syntheticDemoProvider } from '../providers/syntheticDemoProvider';
import { RiskEngine } from '../engines/riskEngine';
import { CsvColumnMapping } from '../types/config';
import { csvDataProvider } from '../providers/csvDataProvider';
import { Validator } from '../pipeline/validator';

export type ProvenanceFilter = 'ALL' | 'REAL_ONLY' | 'SYNTHETIC_ONLY';

export interface NvdSyncStatusInfo {
  connection: string;
  last_synchronization: string | null;
  total_nvd_vulnerabilities: number;
  total_all_vulnerabilities: number;
  last_stats: {
    fetched: number;
    inserted: number;
    updated: number;
    failed: number;
  };
}

interface CrispContextType {
  // State
  isInitialized: boolean;
  isSyncing: boolean;
  lastDataUpdate: string;
  vulnerabilities: Vulnerability[];
  securityEvents: SecurityEvent[];
  assets: Asset[];
  nistControls: NistControlEvaluation[];
  complianceSummary: NistComplianceSummary | null;
  dataSources: DataSourceStatus[];
  pipelineLogs: PipelineExecutionLog[];
  nvdSyncStatus: NvdSyncStatusInfo | null;
  lastSyncStats: { fetched: number; inserted: number; updated: number; failed: number } | null;
  
  // Demo Mode
  isDemoModeActive: boolean;
  demoStreamSpeed: number; // ms
  toggleDemoMode: () => void;
  setDemoStreamSpeed: (ms: number) => void;
  simulateSingleEvent: () => void;
  clearSyntheticEvents: () => void;

  // Actions
  syncNvd: (resultsPerPage?: number) => Promise<{ fetched: number; inserted: number; updated: number; failed: number }>;
  refreshIntelligence: (force?: boolean) => Promise<void>;
  recalculateRisk: () => Promise<void>;
  importCustomCsv: (csvContent: string, mapping: CsvColumnMapping) => Promise<{ count: number; errors: string[] }>;
  executeRawSql: (sql: string) => { columns: string[]; rows: (string | number | null)[][] };
  
  // Filtering & View state
  activeTab: string;
  setActiveTab: (tab: string) => void;
  provenanceFilter: ProvenanceFilter;
  setProvenanceFilter: (filter: ProvenanceFilter) => void;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  selectedAssetId: string | null;
  setSelectedAssetId: (id: string | null) => void;
}

const CrispContext = createContext<CrispContextType | null>(null);

export const CrispProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isInitialized, setIsInitialized] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [lastDataUpdate, setLastDataUpdate] = useState<string>('Initializing...');
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [nistControls, setNistControls] = useState<NistControlEvaluation[]>([]);
  const [complianceSummary, setComplianceSummary] = useState<NistComplianceSummary | null>(null);
  const [dataSources, setDataSources] = useState<DataSourceStatus[]>([]);
  const [pipelineLogs, setPipelineLogs] = useState<PipelineExecutionLog[]>([]);
  const [nvdSyncStatus, setNvdSyncStatus] = useState<NvdSyncStatusInfo | null>(null);
  const [lastSyncStats, setLastSyncStats] = useState<{ fetched: number; inserted: number; updated: number; failed: number } | null>(null);

  // Demo controls
  const [isDemoModeActive, setIsDemoModeActive] = useState(false);
  const [demoStreamSpeed, setDemoStreamSpeed] = useState(3500); // 3.5s interval
  const demoIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // View state
  const [activeTab, setActiveTab] = useState('dashboard');
  const [provenanceFilter, setProvenanceFilter] = useState<ProvenanceFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  // Load state from SQLite
  const reloadFromDatabase = useCallback(() => {
    const vulns = crispDb.getVulnerabilities();
    const evts = crispDb.getSecurityEvents(250);
    const asts = crispDb.getAssets();
    const ctrls = crispDb.getNistControls();
    const sources = crispDb.getDataSourceMetrics();
    const logs = crispDb.getPipelineLogs(20);

    setVulnerabilities(vulns);
    setSecurityEvents(evts);
    setAssets(asts);
    setNistControls(ctrls);
    setDataSources(sources);
    setPipelineLogs(logs);

    // Compute compliance summary from controls
    if (ctrls.length > 0) {
      const avg = Math.round(ctrls.reduce((a, b) => a + b.score, 0) / ctrls.length);
      const funcScores: Record<string, number[]> = {
        GOVERN: [],
        IDENTIFY: [],
        PROTECT: [],
        DETECT: [],
        RESPOND: [],
        RECOVER: [],
      };
      ctrls.forEach((c) => funcScores[c.function]?.push(c.score));

      const calcAvg = (arr: number[]) =>
        arr.length > 0 ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;

      const today = new Date().toISOString().slice(0, 10);
      const overdue = vulns.filter(
        (v) => v.isKnownExploited && v.kevDueDate && v.kevDueDate < today
      ).length;

      setComplianceSummary({
        overallCompliancePct: avg,
        evaluatedAt: new Date().toISOString(),
        functionScores: {
          govern: calcAvg(funcScores.GOVERN),
          identify: calcAvg(funcScores.IDENTIFY),
          protect: calcAvg(funcScores.PROTECT),
          detect: calcAvg(funcScores.DETECT),
          respond: calcAvg(funcScores.RESPOND),
          recover: calcAvg(funcScores.RECOVER),
        },
        totalControls: ctrls.length,
        compliantCount: ctrls.filter((c) => c.status === 'COMPLIANT').length,
        partialCount: ctrls.filter((c) => c.status === 'PARTIAL').length,
        nonCompliantCount: ctrls.filter((c) => c.status === 'NON_COMPLIANT').length,
        kevOverdueCount: overdue,
      });
    }

    setLastDataUpdate(new Date().toLocaleTimeString());

    // Query backend NVD sync status cache
    fetch('/api/nvd/status')
      .then((r) => r.json())
      .then((st) => setNvdSyncStatus(st))
      .catch(() => {});
  }, []);

  // Initialize pipeline
  useEffect(() => {
    let mounted = true;
    async function init() {
      try {
        await pipelineManager.initialize();
        if (mounted) {
          reloadFromDatabase();
          setIsInitialized(true);
        }
      } catch (err) {
        console.error('Initialization error:', err);
      }
    }
    init();
    return () => {
      mounted = false;
    };
  }, [reloadFromDatabase]);

  // Sync NVD implementation
  const syncNvd = async (resultsPerPage = 20) => {
    setIsSyncing(true);
    try {
      const res = await fetch('/api/nvd/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resultsPerPage }),
      });
      const stats = await res.json();
      setLastSyncStats({
        fetched: stats.fetched || 0,
        inserted: stats.inserted || 0,
        updated: stats.updated || 0,
        failed: stats.failed || 0,
      });

      // Ingest latest synchronized NVD records into SQLite client view
      const storedRes = await fetch('/api/nvd/stored?limit=50');
      if (storedRes.ok) {
        const stored = await storedRes.json();
        stored.forEach((item: any) => {
          crispDb.upsertVulnerability({
            id: item.cve_id,
            title: `${item.cve_id} - ${item.affected_products?.[0] || 'Vulnerability'}`,
            description: item.description || 'No description provided.',
            cvssScore: typeof item.cvss_score === 'number' ? item.cvss_score : 0.0,
            severity: item.severity || 'NONE',
            affectedProducts: item.affected_products || [],
            cwe: item.cwe || [],
            publishedDate: item.published_date || new Date().toISOString(),
            modifiedDate: item.modified_date || new Date().toISOString(),
            references: item.references || [],
            isKnownExploited: false,
            dataSource: 'NVD_API',
            isRealData: true,
            lastRetrievedAt: new Date().toISOString(),
          });
        });
      }

      await pipelineManager.recalculateAllRisksAndCompliance();
      reloadFromDatabase();
      return stats;
    } catch (err: any) {
      console.error('NVD sync failed:', err);
      return { fetched: 0, inserted: 0, updated: 0, failed: 1 };
    } finally {
      setIsSyncing(false);
    }
  };

  // Refresh intelligence
  const refreshIntelligence = async (force = true) => {
    setIsSyncing(true);
    try {
      await pipelineManager.syncVulnerabilityIntelligence({ forceRefresh: force });
      reloadFromDatabase();
    } catch (err) {
      console.error('Failed to sync vulnerability intelligence:', err);
    } finally {
      setIsSyncing(false);
    }
  };

  // Recalculate risk
  const recalculateRisk = async () => {
    setIsSyncing(true);
    try {
      await pipelineManager.recalculateAllRisksAndCompliance();
      reloadFromDatabase();
    } catch (err) {
      console.error('Failed to recalculate risk:', err);
    } finally {
      setIsSyncing(false);
    }
  };

  // Simulate a single demo event
  const simulateSingleEvent = useCallback(() => {
    const currentAssets = crispDb.getAssets();
    const newEvent = syntheticDemoProvider.generateLiveEvent(currentAssets);
    crispDb.insertSecurityEvent(newEvent);

    // Auto-update risk for target asset
    const vulns = crispDb.getVulnerabilities();
    const allEvents = crispDb.getSecurityEvents(50);
    const targetAsset = currentAssets.find((a) => a.id === newEvent.assetId);

    if (targetAsset) {
      const breakdown = RiskEngine.calculateAssetRisk(targetAsset, vulns, allEvents);
      crispDb.upsertAsset({
        ...targetAsset,
        calculatedRiskScore: breakdown.overallScore,
      });
    }

    reloadFromDatabase();
  }, [reloadFromDatabase]);

  // Demo Streaming Toggle
  const toggleDemoMode = () => {
    setIsDemoModeActive((prev) => !prev);
  };

  useEffect(() => {
    if (isDemoModeActive) {
      demoIntervalRef.current = setInterval(() => {
        simulateSingleEvent();
      }, demoStreamSpeed);
    } else {
      if (demoIntervalRef.current) {
        clearInterval(demoIntervalRef.current);
        demoIntervalRef.current = null;
      }
    }
    return () => {
      if (demoIntervalRef.current) {
        clearInterval(demoIntervalRef.current);
      }
    };
  }, [isDemoModeActive, demoStreamSpeed, simulateSingleEvent]);

  // Clear demo data
  const clearSyntheticEvents = () => {
    crispDb.executeRawQuery("DELETE FROM security_events WHERE data_source = 'SYNTHETIC_DEMO'");
    pipelineManager.recalculateAllRisksAndCompliance().then(() => reloadFromDatabase());
  };

  // Custom CSV import
  const importCustomCsv = async (csvContent: string, mapping: CsvColumnMapping) => {
    const res = await csvDataProvider.parseCsvString(csvContent, mapping, true);
    if (res.events.length > 0) {
      const valid: SecurityEvent[] = [];
      for (const e of res.events) {
        if (Validator.validateSecurityEvent(e).isValid) {
          valid.push(e);
        }
      }
      crispDb.insertSecurityEvents(valid);
      await pipelineManager.recalculateAllRisksAndCompliance();
      reloadFromDatabase();
    }
    return {
      count: res.validEventsCount,
      errors: res.errors,
    };
  };

  // Raw SQL execution
  const executeRawSql = (sql: string) => {
    return crispDb.executeRawQuery(sql);
  };

  return (
    <CrispContext.Provider
      value={{
        isInitialized,
        isSyncing,
        lastDataUpdate,
        vulnerabilities,
        securityEvents,
        assets,
        nistControls,
        complianceSummary,
        dataSources,
        pipelineLogs,
        nvdSyncStatus,
        lastSyncStats,
        isDemoModeActive,
        demoStreamSpeed,
        toggleDemoMode,
        setDemoStreamSpeed,
        simulateSingleEvent,
        clearSyntheticEvents,
        syncNvd,
        refreshIntelligence,
        recalculateRisk,
        importCustomCsv,
        executeRawSql,
        activeTab,
        setActiveTab,
        provenanceFilter,
        setProvenanceFilter,
        searchQuery,
        setSearchQuery,
        selectedAssetId,
        setSelectedAssetId,
      }}
    >
      {children}
    </CrispContext.Provider>
  );
};

export const useCrisp = () => {
  const context = useContext(CrispContext);
  if (!context) {
    throw new Error('useCrisp must be used within a CrispProvider');
  }
  return context;
};
