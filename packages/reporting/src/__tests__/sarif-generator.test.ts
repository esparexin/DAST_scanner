import { describe, it, expect } from 'vitest';
import { SarifGenerator } from '../sarif-generator.js';
import { Severity, Confidence, FindingStatus, DetectionCategory } from '@securityscan/contracts';
import type { IFinding } from '@securityscan/contracts';

const mockFinding: IFinding = {
  id: 'f1', scanId: 's1', projectId: 'p1', targetId: 't1',
  ruleId: 'SEC-HDR-001', title: 'Missing HSTS', description: 'No HSTS header',
  impact: '', severity: Severity.MEDIUM, confidence: Confidence.CONFIRMED,
  status: FindingStatus.VERIFIED, category: DetectionCategory.MISCONFIGURATION,
  endpoint: 'https://example.com/', method: 'GET', evidenceIds: [],
  remediation: 'Add HSTS', cwe: ['CWE-319'], owasp: ['A05:2021'],
  apiOwasp: [], references: [], deduplicationKey: 'abc',
  firstDetectedAt: new Date(), lastDetectedAt: new Date(),
  createdAt: new Date(), updatedAt: new Date(),
};

describe('SarifGenerator', () => {
  it('generates valid SARIF output', () => {
    const gen = new SarifGenerator();
    const sarif = gen.generate([mockFinding], 'https://example.com');
    const parsed = JSON.parse(sarif);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].results).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.name).toBe('SecurityScan');
  });

  it('maps severity to SARIF level', () => {
    const gen = new SarifGenerator();
    const sarif = JSON.parse(gen.generate([mockFinding], 'https://example.com'));
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });
});
