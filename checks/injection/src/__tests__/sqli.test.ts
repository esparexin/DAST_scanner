import { describe, it, expect, vi } from 'vitest';
import { SqlInjectionChecks } from '../index.js';
import { HttpMethod } from '@securityscan/contracts';

describe('SqlInjectionChecks', () => {
  const checks = SqlInjectionChecks.getChecks();
  const sqliCheck = checks[0]!;

  it('detects database syntax error leaks from quote disruption', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 500,
        headers: { 'content-type': 'text/plain' },
        body: 'PostgreSQL: syntax error at or near "\'" at line 1',
        responseTime: 45,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/items?id=12', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const findings = await sqliCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-SQLI-001');
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[0]?.parameter).toBe('id');
  });

  it('does not trigger on clean normal response', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"items": []}',
        responseTime: 10,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/items?id=12', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const findings = await sqliCheck.run(ctx);
    expect(findings).toHaveLength(0);
  });
});
