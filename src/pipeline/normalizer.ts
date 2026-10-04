/**
 * Pipeline Normalizer
 *
 * Ensures all raw or loosely-typed inputs conform strictly
 * to internal CRISP schemas, sanitizing strings and bounding numeric values.
 */

import { Vulnerability, SecurityEvent } from '../types/schemas';

export class Normalizer {
  static normalizeVulnerability(raw: Partial<Vulnerability>): Vulnerability {
    const cvss = typeof raw.cvssScore === 'number' ? Math.max(0, Math.min(10, raw.cvssScore)) : 0;
    
    let severity: Vulnerability['severity'] = raw.severity || 'MEDIUM';
    if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(severity)) {
      if (cvss >= 9.0) severity = 'CRITICAL';
      else if (cvss >= 7.0) severity = 'HIGH';
      else if (cvss >= 4.0) severity = 'MEDIUM';
      else severity = 'LOW';
    }

    return {
      id: (raw.id || 'CVE-UNKNOWN').toUpperCase().trim(),
      title: raw.title?.trim() || `${raw.id || 'Vulnerability'} Security Advisory`,
      description: raw.description?.trim() || 'No description provided.',
      cvssScore: Number(cvss.toFixed(1)),
      cvssVector: raw.cvssVector?.trim(),
      severity,
      affectedProducts: Array.isArray(raw.affectedProducts) ? raw.affectedProducts.filter(Boolean) : [],
      cwe: Array.isArray(raw.cwe) ? raw.cwe.filter(Boolean) : [],
      publishedDate: raw.publishedDate || new Date().toISOString(),
      modifiedDate: raw.modifiedDate || new Date().toISOString(),
      references: Array.isArray(raw.references) ? raw.references.filter(Boolean) : [],
      isKnownExploited: Boolean(raw.isKnownExploited),
      kevDateAdded: raw.kevDateAdded,
      kevVendorProject: raw.kevVendorProject,
      kevProduct: raw.kevProduct,
      kevVulnerabilityName: raw.kevVulnerabilityName,
      kevRequiredAction: raw.kevRequiredAction,
      kevDueDate: raw.kevDueDate,
      dataSource: raw.dataSource || 'NVD_API',
      isRealData: raw.isRealData ?? true,
      lastRetrievedAt: raw.lastRetrievedAt || new Date().toISOString(),
    };
  }

  static normalizeSecurityEvent(raw: Partial<SecurityEvent>): SecurityEvent {
    let severity: SecurityEvent['severity'] = raw.severity || 'MEDIUM';
    if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].includes(severity)) {
      severity = 'MEDIUM';
    }

    return {
      id: (raw.id || `EVT-${Date.now()}`).trim(),
      timestamp: raw.timestamp || new Date().toISOString(),
      sourceIp: raw.sourceIp?.trim() || '127.0.0.1',
      destinationIp: raw.destinationIp?.trim() || '10.0.0.1',
      assetId: raw.assetId?.trim() || 'AST-UNASSIGNED',
      assetName: raw.assetName?.trim() || 'Unassigned Host',
      assetCriticality: raw.assetCriticality || 'MEDIUM',
      attackCategory: raw.attackCategory || 'Reconnaissance',
      severity,
      description: raw.description?.trim() || 'Security event detected.',
      relatedCveId: raw.relatedCveId?.trim() || undefined,
      detectionRule: raw.detectionRule?.trim() || 'GENERIC_RULE',
      status: raw.status || 'ACTIVE',
      dataSource: raw.dataSource || 'HISTORICAL_DATASET',
      isRealData: raw.isRealData ?? true,
    };
  }
}
