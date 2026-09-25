import { describe, it, expect, beforeEach } from 'vitest';
import { FindingEngine } from '../finding-engine.js';
import { Severity, Confidence, DetectionCategory } from '@securityscan/contracts';
import type { ICreateFinding } from '@securityscan/contracts';

function makeFinding(overrides: Partial<ICreateFinding> = {}): ICreateFinding {
  return {
    scanId: 'scan-1',
    projectId: 'proj-1',
    targetId: 'target-1',
    ruleId: 'SEC-HDR-001',
    title: 'Test Finding',
    description: 'Test description',
    impact: '',
    severity: Severity.MEDIUM,
    confidence: Confidence.CONFIRMED,
    category: DetectionCategory.MISCONFIGURATION,
    endpoint: 'https://example.com/',
    method: 'GET',
    remediation: 'Fix it',
    cwe: ['CWE-319'],
    owasp: ['A05:2021'],
    ...overrides,
  };
}

describe('FindingEngine', () => {
  let engine: FindingEngine;

  beforeEach(() => {
    engine = new FindingEngine();
  });

  it('normalizes a finding with deduplication key', () => {
    const result = engine.normalize(makeFinding());
    expect(result).not.toBeNull();
    expect(result!.deduplicationKey).toHaveLength(32);
    expect(result!.status).toBe('CANDIDATE');
  });

  it('deduplicates identical findings', () => {
    const f1 = engine.normalize(makeFinding());
    const f2 = engine.normalize(makeFinding());
    expect(f1).not.toBeNull();
    expect(f2).toBeNull();
  });

  it('does not deduplicate different endpoints', () => {
    const f1 = engine.normalize(makeFinding({ endpoint: 'https://example.com/a' }));
    const f2 = engine.normalize(makeFinding({ endpoint: 'https://example.com/b' }));
    expect(f1).not.toBeNull();
    expect(f2).not.toBeNull();
  });

  it('does not deduplicate different rules', () => {
    const f1 = engine.normalize(makeFinding({ ruleId: 'SEC-HDR-001' }));
    const f2 = engine.normalize(makeFinding({ ruleId: 'SEC-HDR-002' }));
    expect(f1).not.toBeNull();
    expect(f2).not.toBeNull();
  });

  it('resets deduplication state', () => {
    engine.normalize(makeFinding());
    engine.reset();
    const result = engine.normalize(makeFinding());
    expect(result).not.toBeNull();
  });
});
