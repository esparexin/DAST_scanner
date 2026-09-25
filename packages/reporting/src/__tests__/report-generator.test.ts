import { describe, it, expect } from 'vitest';
import { ReportGenerator } from '../report-generator.js';
import { Severity, Confidence, FindingStatus, DetectionCategory } from '@securityscan/contracts';
import type { IFinding } from '@securityscan/contracts';

const mockFinding: IFinding = {
  id: 'f1',
  scanId: 's1',
  projectId: 'p1',
  targetId: 't1',
  ruleId: 'SEC-HDR-001',
  title: 'Missing HSTS',
  description: 'No Strict-Transport-Security header',
  impact: '',
  severity: Severity.MEDIUM,
  confidence: Confidence.CONFIRMED,
  status: FindingStatus.VERIFIED,
  category: DetectionCategory.MISCONFIGURATION,
  endpoint: 'https://example.com/',
  method: 'GET',
  evidenceIds: [],
  remediation: 'Add HSTS header',
  cwe: ['CWE-319'],
  owasp: ['A05:2021'],
  apiOwasp: [],
  references: [],
  deduplicationKey: 'abc123',
  firstDetectedAt: new Date(),
  lastDetectedAt: new Date(),
  createdAt: new Date(),
  updatedAt: new Date(),
};

describe('ReportGenerator', () => {
  const generator = new ReportGenerator();

  it('generates correct summary', () => {
    const summary = generator.generateSummary([mockFinding]);
    expect(summary.totalFindings).toBe(1);
    expect(summary.mediumCount).toBe(1);
    expect(summary.confirmedCount).toBe(1);
  });

  it('generates valid JSON report', () => {
    const json = generator.generateJSON({
      title: 'Test Report',
      scope: { targetUrl: 'https://example.com', allowedHosts: ['example.com'], excludedHosts: [], scanProfile: 'STANDARD' },
      findings: [mockFinding],
      generatedAt: new Date(),
    });
    const parsed = JSON.parse(json);
    expect(parsed.title).toBe('Test Report');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.summary.totalFindings).toBe(1);
  });

  it('generates valid HTML report', () => {
    const html = generator.generateHTML({
      title: 'Test Report',
      scope: { targetUrl: 'https://example.com', allowedHosts: ['example.com'], excludedHosts: [], scanProfile: 'STANDARD' },
      findings: [mockFinding],
      generatedAt: new Date(),
    });
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('Missing HSTS');
    expect(html).toContain('MEDIUM');
  });

  it('escapes HTML in report', () => {
    const xssFinding = { ...mockFinding, title: '<script>alert(1)</script>' };
    const html = generator.generateHTML({
      title: 'Report',
      scope: { targetUrl: 'https://example.com', allowedHosts: [], excludedHosts: [], scanProfile: 'STANDARD' },
      findings: [xssFinding],
      generatedAt: new Date(),
    });
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
