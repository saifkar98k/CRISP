/**
 * CISA KEV Data Provider
 * Fetches and enriches vulnerability intelligence using the official
 * Cybersecurity and Infrastructure Security Agency (CISA)
 * Known Exploited Vulnerabilities Catalog
 *
 * Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 */

import { Vulnerability } from '../types/schemas';

export interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

export interface CisaKevProviderResult {
  catalog: Map<string, CisaKevEntry>;
  totalCount: number;
  lastUpdated: string;
  sourceStatus: 'CONNECTED' | 'DEGRADED';
  latencyMs: number;
  notes: string;
}

export class CisaKevProvider {
  private kevMap: Map<string, CisaKevEntry> = new Map();
  private lastFetchedAt: number = 0;
  private cacheTtlMs = 60 * 60 * 1000; // 1 hour TTL
  private catalogTitle = 'CISA Known Exploited Vulnerabilities Catalog';

  async loadCatalog(forceRefresh = false): Promise<CisaKevProviderResult> {
    const startTime = performance.now();

    // Check cache
    if (!forceRefresh && this.kevMap.size > 0 && Date.now() - this.lastFetchedAt < this.cacheTtlMs) {
      return {
        catalog: this.kevMap,
        totalCount: this.kevMap.size,
        lastUpdated: new Date(this.lastFetchedAt).toISOString(),
        sourceStatus: 'CONNECTED',
        latencyMs: Math.round(performance.now() - startTime),
        notes: `Served from local memory cache (${this.kevMap.size} KEV entries)`,
      };
    }

    try {
      const response = await fetch('/api/cisa-kev', {
        headers: { Accept: 'application/json' },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch CISA KEV catalog (HTTP ${response.status})`);
      }

      const json = await response.json();
      const vulnerabilities: CisaKevEntry[] = json.vulnerabilities || [];

      this.kevMap.clear();
      for (const entry of vulnerabilities) {
        if (entry.cveID) {
          this.kevMap.set(entry.cveID.toUpperCase(), entry);
        }
      }

      this.lastFetchedAt = Date.now();

      return {
        catalog: this.kevMap,
        totalCount: this.kevMap.size,
        lastUpdated: json.dateReleased || new Date().toISOString(),
        sourceStatus: 'CONNECTED',
        latencyMs: Math.round(performance.now() - startTime),
        notes: `Successfully updated CISA KEV catalog (${this.kevMap.size} total entries)`,
      };
    } catch (err) {
      // If server or network fails, keep existing or load embedded KEV snapshot
      if (this.kevMap.size === 0) {
        this.loadEmbeddedFallback();
      }

      return {
        catalog: this.kevMap,
        totalCount: this.kevMap.size,
        lastUpdated: new Date(this.lastFetchedAt || Date.now()).toISOString(),
        sourceStatus: 'DEGRADED',
        latencyMs: Math.round(performance.now() - startTime),
        notes: `External CISA KEV feed unreachable. Using pre-loaded KEV catalog snapshot (${this.kevMap.size} records).`,
      };
    }
  }

  /**
   * Enriches a single internal Vulnerability record with official CISA KEV data
   */
  enrichVulnerability(vuln: Vulnerability): Vulnerability {
    const cveKey = vuln.id.toUpperCase();
    const kevMatch = this.kevMap.get(cveKey);

    if (kevMatch) {
      return {
        ...vuln,
        isKnownExploited: true,
        kevDateAdded: kevMatch.dateAdded,
        kevVendorProject: kevMatch.vendorProject,
        kevProduct: kevMatch.product,
        kevVulnerabilityName: kevMatch.vulnerabilityName,
        kevRequiredAction: kevMatch.requiredAction,
        kevDueDate: kevMatch.dueDate,
        // Mark data source as enriched if previously only NVD
        dataSource: 'CISA_KEV',
      };
    }

    return vuln;
  }

  /**
   * Bulk enrich multiple vulnerabilities
   */
  enrichVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
    return vulns.map((v) => this.enrichVulnerability(v));
  }

  /**
   * Lookup if a CVE ID is in CISA KEV
   */
  isCveInKev(cveId: string): boolean {
    return this.kevMap.has(cveId.toUpperCase());
  }

  getKevEntry(cveId: string): CisaKevEntry | undefined {
    return this.kevMap.get(cveId.toUpperCase());
  }

  private loadEmbeddedFallback(): void {
    const embeddedKevs: CisaKevEntry[] = [
      {
        cveID: 'CVE-2021-44228',
        vendorProject: 'Apache',
        product: 'Log4j',
        vulnerabilityName: 'Apache Log4j2 Deserialization of Untrusted Data Vulnerability',
        dateAdded: '2021-12-10',
        shortDescription: 'Apache Log4j2 contains an untrusted deserialization flaw allowing remote code execution.',
        requiredAction: 'Apply vendor mitigation and update to version 2.17.1 or higher.',
        dueDate: '2021-12-24',
      },
      {
        cveID: 'CVE-2024-3400',
        vendorProject: 'Palo Alto Networks',
        product: 'PAN-OS',
        vulnerabilityName: 'Palo Alto Networks PAN-OS Command Injection Vulnerability',
        dateAdded: '2024-04-12',
        shortDescription: 'Command injection vulnerability in GlobalProtect feature allowing unauthenticated root RCE.',
        requiredAction: 'Apply hotfix per vendor advisory.',
        dueDate: '2024-04-19',
      },
      {
        cveID: 'CVE-2024-21887',
        vendorProject: 'Ivanti',
        product: 'Connect Secure / Policy Secure',
        vulnerabilityName: 'Ivanti Connect Secure and Policy Secure Command Injection Vulnerability',
        dateAdded: '2024-01-11',
        shortDescription: 'Command injection in web components allows authenticated administrator to execute arbitrary commands.',
        requiredAction: 'Apply patch per vendor security update.',
        dueDate: '2024-01-22',
      },
      {
        cveID: 'CVE-2023-34362',
        vendorProject: 'Progress',
        product: 'MOVEit Transfer',
        vulnerabilityName: 'Progress MOVEit Transfer SQL Injection Vulnerability',
        dateAdded: '2023-06-02',
        shortDescription: 'SQL injection vulnerability allows unauthenticated attacker to gain access to database.',
        requiredAction: 'Apply vendor patches immediately and audit database activity.',
        dueDate: '2023-06-23',
      },
      {
        cveID: 'CVE-2023-4966',
        vendorProject: 'Citrix',
        product: 'NetScaler ADC and Gateway',
        vulnerabilityName: 'Citrix NetScaler ADC and Gateway Buffer Overflow Vulnerability',
        dateAdded: '2023-10-18',
        shortDescription: 'Citrix Bleed memory buffer overflow allows extraction of active session tokens.',
        requiredAction: 'Upgrade to fixed firmware and terminate existing sessions.',
        dueDate: '2023-11-08',
      },
      {
        cveID: 'CVE-2023-22515',
        vendorProject: 'Atlassian',
        product: 'Confluence Data Center and Server',
        vulnerabilityName: 'Atlassian Confluence Data Center and Server Improper Access Control Vulnerability',
        dateAdded: '2023-10-05',
        shortDescription: 'Improper access control in setup wizard allows creating unauthorized admin accounts.',
        requiredAction: 'Upgrade to fixed release or restrict external network access.',
        dueDate: '2023-10-26',
      },
      {
        cveID: 'CVE-2022-22965',
        vendorProject: 'VMware',
        product: 'Spring Framework',
        vulnerabilityName: 'VMware Spring Framework Remote Code Execution Vulnerability',
        dateAdded: '2022-04-04',
        shortDescription: 'Spring4Shell data binding flaw allows arbitrary code execution on Tomcat WAR deployments.',
        requiredAction: 'Upgrade to Spring Framework 5.3.18 or 5.2.20.',
        dueDate: '2022-04-25',
      },
      {
        cveID: 'CVE-2017-0144',
        vendorProject: 'Microsoft',
        product: 'Windows SMBv1',
        vulnerabilityName: 'Microsoft Windows SMBv1 Remote Code Execution Vulnerability',
        dateAdded: '2021-11-03',
        shortDescription: 'EternalBlue vulnerability in SMBv1 exploited by WannaCry and NotPetya.',
        requiredAction: 'Apply MS17-010 and disable SMBv1 across enterprise network.',
        dueDate: '2022-05-03',
      },
      {
        cveID: 'CVE-2024-0012',
        vendorProject: 'Palo Alto Networks',
        product: 'PAN-OS',
        vulnerabilityName: 'Palo Alto Networks PAN-OS Authentication Bypass Vulnerability',
        dateAdded: '2024-11-18',
        shortDescription: 'Authentication bypass in PAN-OS management interface.',
        requiredAction: 'Restrict access to management interface and apply hotfix.',
        dueDate: '2024-12-09',
      },
      {
        cveID: 'CVE-2023-38831',
        vendorProject: 'RARLAB',
        product: 'WinRAR',
        vulnerabilityName: 'RARLAB WinRAR Code Execution Vulnerability',
        dateAdded: '2023-08-24',
        shortDescription: 'File extension spoofing in ZIP archives triggers arbitrary code execution.',
        requiredAction: 'Upgrade to WinRAR 6.23 or newer.',
        dueDate: '2023-09-14',
      },
      {
        cveID: 'CVE-2024-21413',
        vendorProject: 'Microsoft',
        product: 'Outlook',
        vulnerabilityName: 'Microsoft Outlook Remote Code Execution Vulnerability',
        dateAdded: '2024-02-29',
        shortDescription: 'MonikerLink vulnerability in Microsoft Outlook allows remote code execution via malicious links.',
        requiredAction: 'Apply Microsoft February 2024 security updates.',
        dueDate: '2024-03-21',
      },
    ];

    this.kevMap.clear();
    for (const item of embeddedKevs) {
      this.kevMap.set(item.cveID.toUpperCase(), item);
    }
    this.lastFetchedAt = Date.now();
  }
}

export const cisaKevProvider = new CisaKevProvider();
