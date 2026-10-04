/**
 * Pipeline Validator
 *
 * Enforces structural integrity and semantic correctness
 * before any record is permitted to enter the SQLite database layer.
 */

import { Vulnerability, SecurityEvent } from '../types/schemas';

export interface ValidationReport {
  isValid: boolean;
  errors: string[];
}

export class Validator {
  private static IP_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  private static CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

  static validateVulnerability(vuln: Vulnerability): ValidationReport {
    const errors: string[] = [];

    if (!vuln.id) {
      errors.push('Vulnerability ID is required');
    } else if (!this.CVE_REGEX.test(vuln.id)) {
      errors.push(`Invalid CVE format: "${vuln.id}". Expected CVE-YYYY-NNNN.`);
    }

    if (typeof vuln.cvssScore !== 'number' || isNaN(vuln.cvssScore) || vuln.cvssScore < 0 || vuln.cvssScore > 10) {
      errors.push(`CVSS Score out of bounds [0.0 - 10.0]: ${vuln.cvssScore}`);
    }

    if (!vuln.publishedDate || isNaN(new Date(vuln.publishedDate).getTime())) {
      errors.push(`Invalid published date: "${vuln.publishedDate}"`);
    }

    if (vuln.isKnownExploited && !vuln.kevDateAdded) {
      errors.push('Known exploited vulnerability must have KEV date added');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  static validateSecurityEvent(event: SecurityEvent): ValidationReport {
    const errors: string[] = [];

    if (!event.id) {
      errors.push('Event ID is required');
    }

    if (!event.timestamp || isNaN(new Date(event.timestamp).getTime())) {
      errors.push(`Invalid event timestamp: "${event.timestamp}"`);
    }

    if (!event.sourceIp) {
      errors.push('Source IP is required');
    }

    if (!event.destinationIp) {
      errors.push('Destination IP is required');
    }

    if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].includes(event.severity)) {
      errors.push(`Invalid event severity: "${event.severity}"`);
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}
