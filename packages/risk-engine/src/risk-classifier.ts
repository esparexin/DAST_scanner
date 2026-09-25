import { Severity, Confidence, FindingStatus } from '@securityscan/contracts';

export interface RiskScore {
  severity: Severity;
  confidence: Confidence;
  numericScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const SEVERITY_SCORES: Record<Severity, number> = {
  [Severity.CRITICAL]: 10,
  [Severity.HIGH]: 8,
  [Severity.MEDIUM]: 5,
  [Severity.LOW]: 2,
  [Severity.INFO]: 0,
};

const CONFIDENCE_MULTIPLIERS: Record<Confidence, number> = {
  [Confidence.CONFIRMED]: 1.0,
  [Confidence.HIGH]: 0.85,
  [Confidence.MEDIUM]: 0.6,
  [Confidence.LOW]: 0.3,
};

export class RiskClassifier {
  classify(severity: Severity, confidence: Confidence): RiskScore {
    const base = SEVERITY_SCORES[severity] ?? 0;
    const mult = CONFIDENCE_MULTIPLIERS[confidence] ?? 0.5;
    const numericScore = Math.round(base * mult * 10) / 10;

    let riskLevel: RiskScore['riskLevel'];
    if (numericScore >= 9) riskLevel = 'critical';
    else if (numericScore >= 7) riskLevel = 'high';
    else if (numericScore >= 4) riskLevel = 'medium';
    else if (numericScore >= 1) riskLevel = 'low';
    else riskLevel = 'info';

    return { severity, confidence, numericScore, riskLevel };
  }

  /**
   * Determine if a finding should cause a CI/CD pipeline failure.
   */
  shouldFailPipeline(
    severity: Severity,
    confidence: Confidence,
    status: FindingStatus,
    thresholdSeverity: Severity = Severity.HIGH,
  ): boolean {
    if (status !== FindingStatus.VERIFIED && status !== FindingStatus.ACCEPTED) {
      return false;
    }
    const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO];
    return severityOrder.indexOf(severity) <= severityOrder.indexOf(thresholdSeverity);
  }
}
