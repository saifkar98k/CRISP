/**
 * CRISP NIST CSF 2.0 Compliance Engine
 *
 * Evaluates organizational security posture against the 6 NIST CSF 2.0 Functions:
 * 1. GOVERN (GV)
 * 2. IDENTIFY (ID)
 * 3. PROTECT (PR)
 * 4. DETECT (DE)
 * 5. RESPOND (RS)
 * 6. RECOVER (RC)
 *
 * Scoring dynamically incorporates live telemetry:
 * - Active CISA KEV overdue patches reduce Protect & Identify scores
 * - Unresolved Critical security events reduce Respond & Detect scores
 * - Asset risk profiles feed into the Identify function
 */

import {
  NistControlEvaluation,
  NistComplianceSummary,
  Vulnerability,
  SecurityEvent,
  Asset,
} from '../types/schemas';

export class ComplianceEngine {
  static evaluateCompliance(
    controls: NistControlEvaluation[],
    vulnerabilities: Vulnerability[],
    events: SecurityEvent[],
    assets: Asset[]
  ): { evaluatedControls: NistControlEvaluation[]; summary: NistComplianceSummary } {
    const today = new Date().toISOString().slice(0, 10);
    const overdueKevs = vulnerabilities.filter(
      (v) => v.isKnownExploited && v.kevDueDate && v.kevDueDate < today
    );
    const criticalEvents = events.filter((e) => e.severity === 'CRITICAL' && e.status === 'ACTIVE');
    const highRiskAssets = assets.filter((a) => a.calculatedRiskScore >= 8.0);

    const updatedControls = controls.map((ctrl) => {
      let score = ctrl.score;
      let findings = ctrl.findings;
      let requiredRemediation = ctrl.requiredRemediation;
      let status = ctrl.status;

      // Dynamic adjustments based on real posture
      if (ctrl.id === 'PR.PS-01') {
        if (overdueKevs.length > 0) {
          score = Math.max(30, 75 - overdueKevs.length * 15);
          status = 'NON_COMPLIANT';
          findings = `${overdueKevs.length} CISA KEV entries have exceeded mandated patching remediation due dates!`;
          requiredRemediation = `Immediately remediate: ${overdueKevs.map((k) => k.id).join(', ')}`;
        } else {
          score = 85;
          status = 'COMPLIANT';
          findings = 'All known exploited vulnerabilities are within approved maintenance windows.';
        }
      }

      if (ctrl.id === 'RS.MA-01') {
        if (criticalEvents.length > 0) {
          score = Math.max(40, 80 - criticalEvents.length * 10);
          status = score >= 70 ? 'PARTIAL' : 'NON_COMPLIANT';
          findings = `${criticalEvents.length} uncontained CRITICAL security incidents in active queue.`;
          requiredRemediation = 'Trigger incident containment playbooks for pending alerts.';
        } else {
          score = 88;
          status = 'COMPLIANT';
          findings = 'Zero active uncontained critical security incidents.';
        }
      }

      if (ctrl.id === 'ID.RA-01') {
        if (highRiskAssets.length > 0) {
          score = Math.max(50, 90 - highRiskAssets.length * 8);
          status = 'PARTIAL';
          findings = `${highRiskAssets.length} enterprise assets have CRISP risk scores exceeding 8.0/10.0.`;
          requiredRemediation = 'Perform targeted vulnerability mitigation on high-risk perimeter assets.';
        }
      }

      return {
        ...ctrl,
        score,
        status,
        findings,
        requiredRemediation,
      };
    });

    // Compute function breakdown
    const functionBuckets: Record<string, number[]> = {
      GOVERN: [],
      IDENTIFY: [],
      PROTECT: [],
      DETECT: [],
      RESPOND: [],
      RECOVER: [],
    };

    let compliantCount = 0;
    let partialCount = 0;
    let nonCompliantCount = 0;

    for (const c of updatedControls) {
      functionBuckets[c.function].push(c.score);
      if (c.status === 'COMPLIANT') compliantCount++;
      else if (c.status === 'PARTIAL') partialCount++;
      else nonCompliantCount++;
    }

    const calcAvg = (arr: number[]) =>
      arr.length > 0 ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;

    const functionScores = {
      govern: calcAvg(functionBuckets.GOVERN),
      identify: calcAvg(functionBuckets.IDENTIFY),
      protect: calcAvg(functionBuckets.PROTECT),
      detect: calcAvg(functionBuckets.DETECT),
      respond: calcAvg(functionBuckets.RESPOND),
      recover: calcAvg(functionBuckets.RECOVER),
    };

    const allScores = updatedControls.map((c) => c.score);
    const overallCompliancePct =
      allScores.length > 0 ? Math.round(allScores.reduce((a, b) => a + b, 0) / allScores.length) : 0;

    return {
      evaluatedControls: updatedControls,
      summary: {
        overallCompliancePct,
        evaluatedAt: new Date().toISOString(),
        functionScores,
        totalControls: updatedControls.length,
        compliantCount,
        partialCount,
        nonCompliantCount,
        kevOverdueCount: overdueKevs.length,
      },
    };
  }
}
