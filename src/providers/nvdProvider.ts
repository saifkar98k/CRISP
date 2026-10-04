/**
 * NVD Data Provider
 * Fetches real public vulnerability intelligence from NIST NVD API 2.0
 *
 * Implements:
 * - Timeout handling (with AbortController)
 * - Exponential backoff retry handling with jitter
 * - Rate-limit compliance (NVD public tier: 5 requests / 30 seconds)
 * - Cache check to prevent re-querying on every dashboard refresh
 * - Duplicate prevention & deduplication
 * - Fallback to curated real CVE snapshot when NVD is rate-limited or unavailable
 */

import { Vulnerability } from '../types/schemas';
import curatedCatalog from '../data/curated_cve_catalog.json';

export interface NvdFetchOptions {
  keywordSearch?: string;
  cveId?: string;
  resultsPerPage?: number;
  startIndex?: number;
  forceRefresh?: boolean;
}

export interface NvdProviderResult {
  vulnerabilities: Vulnerability[];
  totalResults: number;
  isFromCache: boolean;
  isRealData: true;
  sourceStatus: 'CONNECTED' | 'RATE_LIMITED' | 'DEGRADED';
  latencyMs: number;
  notes: string;
}

export class NvdProvider {
  private cache: Map<string, { data: Vulnerability[]; timestamp: number }> = new Map();
  private cacheTtlMs = 15 * 60 * 1000; // 15 minutes TTL
  private lastRequestTime = 0;
  private minIntervalMs = 6000; // Rate limit guard (6 seconds between public requests)

  async fetchVulnerabilities(options: NvdFetchOptions = {}): Promise<NvdProviderResult> {
    const startTime = performance.now();
    const cacheKey = JSON.stringify(options);

    // 1. Check local in-memory cache unless forced
    if (!options.forceRefresh && this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey)!;
      if (Date.now() - cached.timestamp < this.cacheTtlMs) {
        return {
          vulnerabilities: cached.data,
          totalResults: cached.data.length,
          isFromCache: true,
          isRealData: true,
          sourceStatus: 'CONNECTED',
          latencyMs: Math.round(performance.now() - startTime),
          notes: 'Served from NVD Provider local memory cache (TTL: 15m)',
        };
      }
    }

    // 2. Build URL parameters
    const params = new URLSearchParams();
    const limit = options.resultsPerPage || 15;
    params.set('resultsPerPage', String(Math.min(limit, 25)));
    params.set('startIndex', String(options.startIndex || 0));

    if (options.cveId) {
      params.set('cveId', options.cveId.trim());
    } else if (options.keywordSearch) {
      params.set('keywordSearch', options.keywordSearch.trim());
    }

    const nvdUrl = `/api/nvd?${params.toString()}`;

    // 3. Rate-limit pacing
    const now = Date.now();
    const elapsedSinceLast = now - this.lastRequestTime;
    if (elapsedSinceLast < this.minIntervalMs) {
      const waitTime = this.minIntervalMs - elapsedSinceLast;
      await new Promise((resolve) => setTimeout(resolve, waitTime));
    }
    this.lastRequestTime = Date.now();

    // 4. Fetch with Retry and Timeout
    let lastError: Error | null = null;
    const maxRetries = 2;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 9000); // 9 sec timeout

        const response = await fetch(nvdUrl, {
          signal: controller.signal,
          headers: {
            Accept: 'application/json',
          },
        });
        clearTimeout(timeoutId);

        if (response.status === 429 || response.status === 503) {
          throw new Error(`NVD API Rate Limited or Unavailable (HTTP ${response.status})`);
        }

        if (!response.ok) {
          throw new Error(`NVD API error response: HTTP ${response.status}`);
        }

        const data = await response.json();
        const normalized = this.normalizeNvdResponse(data);

        // Update cache
        this.cache.set(cacheKey, {
          data: normalized,
          timestamp: Date.now(),
        });

        return {
          vulnerabilities: normalized,
          totalResults: data.totalResults || normalized.length,
          isFromCache: false,
          isRealData: true,
          sourceStatus: 'CONNECTED',
          latencyMs: Math.round(performance.now() - startTime),
          notes: `Successfully queried live NVD API 2.0 (Retrieved ${normalized.length} records)`,
        };
      } catch (err) {
        lastError = err as Error;
        // Jittered backoff if not last attempt
        if (attempt < maxRetries) {
          const backoff = Math.pow(2, attempt) * 1000 + Math.random() * 500;
          await new Promise((r) => setTimeout(r, backoff));
        }
      }
    }

    // 5. Fallback gracefully to verified Curated Real NVD CVE snapshot
    // Never leave the dashboard broken
    const fallbackVulns = this.getFallbackCatalog(options);
    return {
      vulnerabilities: fallbackVulns,
      totalResults: fallbackVulns.length,
      isFromCache: true,
      isRealData: true,
      sourceStatus: lastError?.message.includes('Rate') ? 'RATE_LIMITED' : 'DEGRADED',
      latencyMs: Math.round(performance.now() - startTime),
      notes: `External NVD endpoint degraded (${lastError?.message || 'Timeout'}). Preserved continuity using verified local NVD snapshot.`,
    };
  }

  /**
   * Normalizes raw NVD 2.0 JSON schema into the internal CRISP Vulnerability schema
   */
  private normalizeNvdResponse(nvdJson: any): Vulnerability[] {
    if (!nvdJson || !nvdJson.vulnerabilities || !Array.isArray(nvdJson.vulnerabilities)) {
      return [];
    }

    const results: Vulnerability[] = [];
    const seenCves = new Set<string>();

    for (const item of nvdJson.vulnerabilities) {
      const cveObj = item.cve;
      if (!cveObj || !cveObj.id) continue;

      const cveId = cveObj.id;
      if (seenCves.has(cveId)) continue;
      seenCves.add(cveId);

      // Extract description
      const descObj = (cveObj.descriptions || []).find((d: any) => d.lang === 'en') || cveObj.descriptions?.[0];
      const description = descObj?.value || 'No description provided by NVD.';

      // Extract CVSS v3.1 or v3.0 or v2.0
      let cvssScore = 0.0;
      let cvssVector: string | undefined;
      let severity: Vulnerability['severity'] = 'MEDIUM';

      const metrics = cveObj.metrics || {};
      const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
      const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
      const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;

      if (cvss31) {
        cvssScore = Number(cvss31.baseScore || 0);
        cvssVector = cvss31.vectorString;
        severity = this.mapCvssSeverity(cvss31.baseSeverity || cvssScore);
      } else if (cvss30) {
        cvssScore = Number(cvss30.baseScore || 0);
        cvssVector = cvss30.vectorString;
        severity = this.mapCvssSeverity(cvss30.baseSeverity || cvssScore);
      } else if (cvss2) {
        cvssScore = Number(cvss2.baseScore || 0);
        cvssVector = cvss2.vectorString;
        severity = this.mapCvssSeverity(cvssScore);
      }

      // Extract CWE
      const cweList: string[] = [];
      if (cveObj.weaknesses) {
        for (const w of cveObj.weaknesses) {
          for (const desc of w.description || []) {
            if (desc.value && !desc.value.startsWith('NVD-')) {
              cweList.push(desc.value);
            }
          }
        }
      }

      // Extract affected products from configurations
      const products: string[] = [];
      if (cveObj.configurations) {
        for (const config of cveObj.configurations) {
          for (const node of config.nodes || []) {
            for (const match of node.cpeMatch || []) {
              if (match.criteria) {
                const parts = match.criteria.split(':');
                if (parts.length > 4) {
                  const vendor = parts[3];
                  const product = parts[4];
                  const name = `${vendor} ${product}`.replace(/_/g, ' ');
                  if (!products.includes(name)) {
                    products.push(name);
                  }
                }
              }
            }
          }
        }
      }

      // Extract references
      const references: string[] = (cveObj.references || [])
        .map((r: any) => r.url)
        .filter(Boolean)
        .slice(0, 5);

      results.push({
        id: cveId,
        title: `${cveId} - ${products[0] ? products[0].toUpperCase() : 'Vulnerability'}`,
        description,
        cvssScore,
        cvssVector,
        severity,
        affectedProducts: products.slice(0, 6),
        cwe: cweList.slice(0, 4),
        publishedDate: cveObj.published || new Date().toISOString(),
        modifiedDate: cveObj.lastModified || new Date().toISOString(),
        references,
        isKnownExploited: false, // Default false until enriched by CISA KEV
        dataSource: 'NVD_API',
        isRealData: true,
        lastRetrievedAt: new Date().toISOString(),
      });
    }

    return results;
  }

  private mapCvssSeverity(val: string | number): Vulnerability['severity'] {
    if (typeof val === 'string') {
      const upper = val.toUpperCase();
      if (upper === 'CRITICAL') return 'CRITICAL';
      if (upper === 'HIGH') return 'HIGH';
      if (upper === 'MEDIUM') return 'MEDIUM';
      if (upper === 'LOW') return 'LOW';
    }
    const score = Number(val);
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0.0) return 'LOW';
    return 'UNKNOWN';
  }

  private getFallbackCatalog(options: NvdFetchOptions): Vulnerability[] {
    let list = (curatedCatalog as any[]) as Vulnerability[];
    if (options.cveId) {
      list = list.filter((v) => v.id.toLowerCase().includes(options.cveId!.toLowerCase()));
    } else if (options.keywordSearch) {
      const q = options.keywordSearch.toLowerCase();
      list = list.filter(
        (v) =>
          v.id.toLowerCase().includes(q) ||
          v.title.toLowerCase().includes(q) ||
          v.description.toLowerCase().includes(q)
      );
    }
    return list.slice(0, options.resultsPerPage || 15);
  }
}

export const nvdProvider = new NvdProvider();
