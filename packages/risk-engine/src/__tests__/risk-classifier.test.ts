import { describe, it, expect } from 'vitest';
import { RiskClassifier } from '../risk-classifier.js';
import { Severity, Confidence, FindingStatus } from '@securityscan/contracts';

describe('RiskClassifier', () => {
  const classifier = new RiskClassifier();

  it('classifies critical confirmed as critical', () => {
    const score = classifier.classify(Severity.CRITICAL, Confidence.CONFIRMED);
    expect(score.riskLevel).toBe('critical');
    expect(score.numericScore).toBe(10);
  });

  it('classifies high with medium confidence as medium', () => {
    const score = classifier.classify(Severity.HIGH, Confidence.MEDIUM);
    expect(score.riskLevel).toBe('medium');
  });

  it('classifies info as info', () => {
    const score = classifier.classify(Severity.INFO, Confidence.CONFIRMED);
    expect(score.riskLevel).toBe('info');
    expect(score.numericScore).toBe(0);
  });

  it('shouldFailPipeline returns true for verified critical', () => {
    expect(classifier.shouldFailPipeline(Severity.CRITICAL, Confidence.CONFIRMED, FindingStatus.VERIFIED)).toBe(true);
  });

  it('shouldFailPipeline returns false for candidate', () => {
    expect(classifier.shouldFailPipeline(Severity.CRITICAL, Confidence.CONFIRMED, FindingStatus.CANDIDATE)).toBe(false);
  });

  it('shouldFailPipeline returns false for low when threshold is HIGH', () => {
    expect(classifier.shouldFailPipeline(Severity.LOW, Confidence.CONFIRMED, FindingStatus.VERIFIED, Severity.HIGH)).toBe(false);
  });
});
