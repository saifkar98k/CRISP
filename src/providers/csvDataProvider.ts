/**
 * Generic Configurable CSV / JSON Data Provider
 *
 * Imports external cybersecurity incident logs / telemetry datasets
 * and maps them into the CRISP internal SecurityEvent schema using
 * a customizable column configuration.
 */

import Papa from 'papaparse';
import { SecurityEvent } from '../types/schemas';
import { CsvColumnMapping } from '../types/config';

export interface CsvImportResult {
  events: SecurityEvent[];
  totalRowsRead: number;
  validEventsCount: number;
  skippedRowCount: number;
  errors: string[];
  mappingUsed: CsvColumnMapping;
  isRealData: boolean;
}

export class CSVDataProvider {
  /**
   * Parse raw CSV text using the specified column mapping
   */
  async parseCsvString(
    csvContent: string,
    mapping: CsvColumnMapping,
    isRealDataset = true
  ): Promise<CsvImportResult> {
    return new Promise((resolve) => {
      Papa.parse(csvContent, {
        header: true,
        skipEmptyLines: true,
        delimiter: mapping.delimiter || ',',
        complete: (results) => {
          const events: SecurityEvent[] = [];
          const errors: string[] = [];
          const rawRows = results.data as Record<string, string>[];

          if (!rawRows || rawRows.length === 0) {
            resolve({
              events: [],
              totalRowsRead: 0,
              validEventsCount: 0,
              skippedRowCount: 0,
              errors: ['Empty CSV content or no rows detected.'],
              mappingUsed: mapping,
              isRealData: isRealDataset,
            });
            return;
          }

          // Check if required columns exist in the header
          const firstRow = rawRows[0];
          const headers = Object.keys(firstRow);

          const requiredMapped = [
            mapping.idColumn,
            mapping.timestampColumn,
            mapping.sourceIpColumn,
            mapping.destinationIpColumn,
            mapping.descriptionColumn,
          ];

          for (const reqCol of requiredMapped) {
            if (!headers.includes(reqCol)) {
              errors.push(`Missing required mapped column in CSV: "${reqCol}"`);
            }
          }

          if (errors.length > 0) {
            resolve({
              events: [],
              totalRowsRead: rawRows.length,
              validEventsCount: 0,
              skippedRowCount: rawRows.length,
              errors,
              mappingUsed: mapping,
              isRealData: isRealDataset,
            });
            return;
          }

          let skippedCount = 0;

          rawRows.forEach((row, idx) => {
            const rawId = row[mapping.idColumn]?.trim();
            const rawTimestamp = row[mapping.timestampColumn]?.trim();
            const rawSrcIp = row[mapping.sourceIpColumn]?.trim();
            const rawDestIp = row[mapping.destinationIpColumn]?.trim();
            const rawDesc = row[mapping.descriptionColumn]?.trim();

            if (!rawId || !rawTimestamp) {
              skippedCount++;
              return;
            }

            // Normalization & Fallbacks
            const rawSeverity = (mapping.severityColumn && row[mapping.severityColumn]) || mapping.defaultSeverity || 'MEDIUM';
            const rawCategory = (mapping.attackCategoryColumn && row[mapping.attackCategoryColumn]) || mapping.defaultAttackCategory || 'Reconnaissance';
            const rawAssetId = (mapping.assetIdColumn && row[mapping.assetIdColumn]?.trim()) || 'AST-AUTO-GEN';
            const rawAssetName = (mapping.assetNameColumn && row[mapping.assetNameColumn]?.trim()) || rawDestIp || 'Target Host';
            const rawTier = (mapping.assetCriticalityColumn && row[mapping.assetCriticalityColumn]?.trim()) || 'MEDIUM';
            const rawCve = mapping.relatedCveColumn ? row[mapping.relatedCveColumn]?.trim() : undefined;
            const rawRule = (mapping.detectionRuleColumn && row[mapping.detectionRuleColumn]?.trim()) || 'SURICATA_RULE_MATCH';
            const rawStatus = (mapping.statusColumn && row[mapping.statusColumn]?.trim()) || 'ACTIVE';

            // Validate / Normalize Severity
            const severity = this.normalizeSeverity(rawSeverity);
            const attackCategory = this.normalizeAttackCategory(rawCategory);
            const assetCriticality = this.normalizeCriticality(rawTier);
            const status = this.normalizeStatus(rawStatus);

            // Normalize Timestamp to valid ISO string
            let parsedDate: string;
            try {
              const d = new Date(rawTimestamp);
              parsedDate = isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
            } catch {
              parsedDate = new Date().toISOString();
            }

            events.push({
              id: rawId,
              timestamp: parsedDate,
              sourceIp: rawSrcIp || '0.0.0.0',
              destinationIp: rawDestIp || '10.0.0.1',
              assetId: rawAssetId,
              assetName: rawAssetName,
              assetCriticality,
              attackCategory,
              severity,
              description: rawDesc || 'Security anomaly detected in external log telemetry.',
              relatedCveId: rawCve && rawCve.startsWith('CVE-') ? rawCve : undefined,
              detectionRule: rawRule,
              status,
              dataSource: 'HISTORICAL_DATASET',
              isRealData: isRealDataset,
            });
          });

          resolve({
            events,
            totalRowsRead: rawRows.length,
            validEventsCount: events.length,
            skippedRowCount: skippedCount,
            errors,
            mappingUsed: mapping,
            isRealData: isRealDataset,
          });
        },
        error: (err: Error) => {
          resolve({
            events: [],
            totalRowsRead: 0,
            validEventsCount: 0,
            skippedRowCount: 0,
            errors: [err.message],
            mappingUsed: mapping,
            isRealData: isRealDataset,
          });
        },
      });
    });
  }

  private normalizeSeverity(val: string): SecurityEvent['severity'] {
    const s = String(val).toUpperCase();
    if (s.includes('CRIT')) return 'CRITICAL';
    if (s.includes('HIGH')) return 'HIGH';
    if (s.includes('MED')) return 'MEDIUM';
    if (s.includes('LOW')) return 'LOW';
    if (s.includes('INFO')) return 'INFORMATIONAL';
    return 'MEDIUM';
  }

  private normalizeAttackCategory(val: string): SecurityEvent['attackCategory'] {
    const c = String(val).toLowerCase();
    if (c.includes('public') || c.includes('exploit') || c.includes('external')) return 'Exploit Public-Facing App';
    if (c.includes('brute') || c.includes('auth') || c.includes('password') || c.includes('credential')) return 'Brute Force';
    if (c.includes('rce') || c.includes('remote code') || c.includes('execution')) return 'Remote Code Execution';
    if (c.includes('c2') || c.includes('command') || c.includes('beacon') || c.includes('control')) return 'Command & Control';
    if (c.includes('priv') || c.includes('escalat') || c.includes('kerberoast')) return 'Privilege Escalation';
    if (c.includes('dos') || c.includes('denial') || c.includes('flood')) return 'Denial of Service';
    if (c.includes('sql') || c.includes('injection')) return 'SQL Injection';
    if (c.includes('exfil') || c.includes('data transfer') || c.includes('leak')) return 'Data Exfiltration';
    return 'Reconnaissance';
  }

  private normalizeCriticality(val: string): SecurityEvent['assetCriticality'] {
    const c = String(val).toUpperCase();
    if (c.includes('CRIT') || c === '1' || c === 'TIER-1') return 'CRITICAL';
    if (c.includes('HIGH') || c === '2' || c === 'TIER-2') return 'HIGH';
    if (c.includes('MED') || c === '3' || c === 'TIER-3') return 'MEDIUM';
    return 'LOW';
  }

  private normalizeStatus(val: string): SecurityEvent['status'] {
    const s = String(val).toUpperCase();
    if (s.includes('RESOLV')) return 'RESOLVED';
    if (s.includes('CONTAIN')) return 'CONTAINED';
    if (s.includes('INVESTIGAT')) return 'INVESTIGATING';
    return 'ACTIVE';
  }
}

export const csvDataProvider = new CSVDataProvider();
