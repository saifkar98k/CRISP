/**
 * CRISP Multi-Factor Cyber Risk Engine
 *
 * Implements a transparent, deterministic risk scoring formula:
 * Evaluates:
 * 1. CVSS Base Score (Vulnerability severity)
 * 2. CISA KEV Known Exploited Status (Weaponization factor)
 * 3. Asset Business Criticality
 * 4. Network Exposure Tier (External, DMZ, Internal, Isolated)
 * 5. Event Telemetry Frequency (Active exploit attempts observed)
 * 6. Attack Category Hazard
 *
 * TRANSPARENCY REQUIREMENT:
 * Every calculated score produces an itemized breakdown of contributing
 * factors and includes an explicit disclaimer stating it is NOT an official NIST score.
 */

import {
  Vulnerability,
  Asset,
  SecurityEvent,
  RiskScoreBreakdown,
  RiskFactorContribution,
} from '../types/schemas';

export class RiskEngine {
  static readonly DISCLAIMER =
    'CRISP Composite Risk Score is an operational multi-factor cybersecurity metric derived from CVSS, CISA KEV weaponization intelligence, asset criticality, exposure tier, and active event frequency. It is an engineering calculation and is NOT an official NIST score.';

  /**
   * Calculates composite risk for an asset evaluated in context of associated
   * vulnerabilities and observed security event telemetry.
   */
  static calculateAssetRisk(
    asset: Asset,
    associatedVulns: Vulnerability[],
    recentEvents: SecurityEvent[]
  ): RiskScoreBreakdown {
    const factors: RiskFactorContribution[] = [];

    // 1. Highest CVSS Factor (Weight: 30%)
    let maxCvss = 0.0;
    let topVuln: Vulnerability | undefined;
    for (const v of associatedVulns) {
      if (v.cvssScore > maxCvss) {
        maxCvss = v.cvssScore;
        topVuln = v;
      }
    }
    const cvssContribution = Number((maxCvss * 0.30).toFixed(2));
    factors.push({
      factor: 'CVSS Base Score',
      value: topVuln ? `${topVuln.id} (${maxCvss.toFixed(1)})` : 'None (0.0)',
      weight: 0.30,
      scoreContribution: cvssContribution,
      description: topVuln
        ? `Highest CVSS base severity observed: ${maxCvss} on ${topVuln.id}`
        : 'No known unmitigated CVEs assigned to this asset.',
    });

    // 2. CISA KEV Weaponization Status (Weight: 25%)
    const kevVulns = associatedVulns.filter((v) => v.isKnownExploited);
    let kevContribution = 0.0;
    if (kevVulns.length > 0) {
      kevContribution = 2.50;
      // Bonus if overdue
      const nowIso = new Date().toISOString().slice(0, 10);
      const isOverdue = kevVulns.some((v) => v.kevDueDate && v.kevDueDate < nowIso);
      if (isOverdue) kevContribution += 0.50;
    }
    kevContribution = Number(kevContribution.toFixed(2));

    factors.push({
      factor: 'CISA KEV Weaponization',
      value: kevVulns.length > 0 ? `YES (${kevVulns.length} KEVs)` : 'NO (Unlisted)',
      weight: 0.25,
      scoreContribution: kevContribution,
      description:
        kevVulns.length > 0
          ? `Vulnerability actively exploited in the wild: ${kevVulns.map((v) => v.id).join(', ')}`
          : 'No actively exploited vulnerabilities listed in CISA catalog.',
    });

    // 3. Asset Business Criticality Factor (Weight: 20%)
    let critContribution = 0.30;
    if (asset.criticality === 'CRITICAL') critContribution = 2.00;
    else if (asset.criticality === 'HIGH') critContribution = 1.40;
    else if (asset.criticality === 'MEDIUM') critContribution = 0.80;

    factors.push({
      factor: 'Asset Business Criticality',
      value: asset.criticality,
      weight: 0.20,
      scoreContribution: critContribution,
      description: `Asset designated as ${asset.criticality} tier for organizational operations.`,
    });

    // 4. Network Exposure Tier (Weight: 15%)
    let exposureContribution = 0.10;
    if (asset.exposure === 'EXTERNAL') exposureContribution = 1.50;
    else if (asset.exposure === 'DMZ') exposureContribution = 1.00;
    else if (asset.exposure === 'INTERNAL') exposureContribution = 0.50;

    factors.push({
      factor: 'Network Exposure',
      value: asset.exposure,
      weight: 0.15,
      scoreContribution: exposureContribution,
      description:
        asset.exposure === 'EXTERNAL'
          ? 'Directly exposed to public internet with zero perimeter isolation.'
          : `Network placement within ${asset.exposure} perimeter boundary.`,
    });

    // 5. Active Telemetry & Event Frequency (Weight: 10%)
    const matchingEvents = recentEvents.filter(
      (e) => e.assetId === asset.id || e.destinationIp === asset.ipAddress
    );
    let freqContribution = 0.0;
    if (matchingEvents.length >= 5) freqContribution = 1.00;
    else if (matchingEvents.length >= 2) freqContribution = 0.60;
    else if (matchingEvents.length === 1) freqContribution = 0.30;

    factors.push({
      factor: 'Active Event Frequency',
      value: `${matchingEvents.length} events`,
      weight: 0.10,
      scoreContribution: freqContribution,
      description: `${matchingEvents.length} security alerts detected targeting this asset in recent telemetry.`,
    });

    // Sum and clamp to [0.0, 10.0]
    const rawTotal = factors.reduce((acc, f) => acc + f.scoreContribution, 0);
    const overallScore = Number(Math.min(10.0, Math.max(0.0, rawTotal)).toFixed(1));

    let severityTier: RiskScoreBreakdown['severityTier'] = 'LOW';
    if (overallScore >= 9.0) severityTier = 'CRITICAL';
    else if (overallScore >= 7.0) severityTier = 'HIGH';
    else if (overallScore >= 4.0) severityTier = 'MEDIUM';

    const formulaExplanation =
      `CRISP Score = min(10.0, CVSS(${cvssContribution}) + KEV(${kevContribution}) + ` +
      `Criticality(${critContribution}) + Exposure(${exposureContribution}) + Frequency(${freqContribution})) = ${overallScore}`;

    return {
      targetId: asset.id,
      targetType: 'ASSET',
      overallScore,
      severityTier,
      calculatedAt: new Date().toISOString(),
      factors,
      formulaExplanation,
      isDerivedScore: true,
      disclaimer: this.DISCLAIMER,
    };
  }

  /**
   * Calculates standalone risk for a Vulnerability record incorporating KEV status
   */
  static calculateVulnerabilityRisk(vuln: Vulnerability): RiskScoreBreakdown {
    const factors: RiskFactorContribution[] = [];

    // Base CVSS
    const cvssScore = vuln.cvssScore;
    const cvssContrib = Number((cvssScore * 0.65).toFixed(2));
    factors.push({
      factor: 'CVSS Base Score',
      value: cvssScore.toFixed(1),
      weight: 0.65,
      scoreContribution: cvssContrib,
      description: `Official CVSS v3.x score: ${cvssScore} (${vuln.severity})`,
    });

    // CISA KEV Booster
    const kevContrib = vuln.isKnownExploited ? 3.50 : 0.00;
    factors.push({
      factor: 'CISA Known Exploited Status',
      value: vuln.isKnownExploited ? 'CONFIRMED EXPLOITED' : 'NOT EXPLOITED',
      weight: 0.35,
      scoreContribution: kevContrib,
      description: vuln.isKnownExploited
        ? `Added to CISA KEV on ${vuln.kevDateAdded || 'N/A'}. Due date: ${vuln.kevDueDate || 'N/A'}`
        : 'Not recorded in CISA Known Exploited catalog.',
    });

    const rawTotal = cvssContrib + kevContrib;
    const overallScore = Number(Math.min(10.0, Math.max(0.0, rawTotal)).toFixed(1));

    let severityTier: RiskScoreBreakdown['severityTier'] = 'LOW';
    if (overallScore >= 9.0) severityTier = 'CRITICAL';
    else if (overallScore >= 7.0) severityTier = 'HIGH';
    else if (overallScore >= 4.0) severityTier = 'MEDIUM';

    return {
      targetId: vuln.id,
      targetType: 'VULNERABILITY',
      overallScore,
      severityTier,
      calculatedAt: new Date().toISOString(),
      factors,
      formulaExplanation: `Score = min(10.0, (CVSS * 0.65) + KEV_BOOSTER) = ${overallScore}`,
      isDerivedScore: true,
      disclaimer: this.DISCLAIMER,
    };
  }
}
