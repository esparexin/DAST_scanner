import { describe, it, expect } from 'vitest';
import { DetectionEngine } from '../detection-engine.js';
import type { SecurityCheck, CheckContext, CheckResult } from '../types.js';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

describe('DetectionEngine', () => {
  const dummyRule = {
    id: 'SEC-TEST-001',
    name: 'Test Check Rule',
    description: 'A mock rule for testing detection engine',
    category: DetectionCategory.MISCONFIGURATION,
    type: DetectionType.PASSIVE,
    severity: Severity.LOW,
    confidence: Confidence.CONFIRMED,
    owasp: ['A05:2021'],
    apiOwasp: [],
    cwe: ['CWE-693'],
    wstg: [],
    portswigger: [],
    remediation: 'Apply fix',
    references: [],
    enabled: true,
    tags: ['test'],
  };

  const dummyCheck: SecurityCheck = {
    rule: dummyRule,
    async run(ctx: CheckContext): Promise<CheckResult[]> {
      return [
        {
          ruleId: dummyRule.id,
          title: dummyRule.name,
          description: dummyRule.description,
          impact: '',
          severity: dummyRule.severity,
          confidence: dummyRule.confidence,
          category: dummyRule.category,
          endpoint: ctx.endpoint.url,
          method: 'GET',
          remediation: dummyRule.remediation,
          cwe: dummyRule.cwe,
          owasp: dummyRule.owasp,
          apiOwasp: dummyRule.apiOwasp,
          references: dummyRule.references,
          evidence: {
            request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
            response: { statusCode: 200, headers: {}, responseTime: 10 },
          },
        },
      ];
    },
  };

  it('registers and retrieves enabled checks', () => {
    const engine = new DetectionEngine();
    engine.register(dummyCheck);
    const checks = engine.getChecks();
    expect(checks).toHaveLength(1);
    expect(checks[0]?.rule.id).toBe('SEC-TEST-001');
  });

  it('filters checks by category', () => {
    const engine = new DetectionEngine();
    engine.register(dummyCheck);
    expect(engine.getChecks(DetectionCategory.MISCONFIGURATION)).toHaveLength(1);
    expect(engine.getChecks(DetectionCategory.XSS)).toHaveLength(0);
  });

  it('executes checks through runAll', async () => {
    const engine = new DetectionEngine();
    engine.register(dummyCheck);

    const mockContext: any = {
      scanId: 'scan-1',
      targetId: 'target-1',
      projectId: 'proj-1',
      endpoint: {
        id: 'ep-1',
        url: 'https://example.com/test',
        method: HttpMethod.GET,
      },
      baseUrl: 'https://example.com',
    };

    const results = await engine.runAll(mockContext);
    expect(results).toHaveLength(1);
    expect(results[0]?.ruleId).toBe('SEC-TEST-001');
    expect(results[0]?.endpoint).toBe('https://example.com/test');
  });
});
