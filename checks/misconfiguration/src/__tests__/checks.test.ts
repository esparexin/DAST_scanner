import { describe, it, expect, vi } from 'vitest';
import { SecurityHeaderChecks } from '../security-headers.js';
import { CorsChecks } from '../cors-checks.js';
import { InfoDisclosureChecks } from '../info-disclosure.js';
import { HttpMethod } from '@securityscan/contracts';

describe('Security Header Checks', () => {
  const checks = SecurityHeaderChecks.getChecks();

  it('provides HSTS, XCTO, XFO, and CSP checks', () => {
    const ids = checks.map((c) => c.rule.id);
    expect(ids).toContain('SEC-HDR-001');
    expect(ids).toContain('SEC-HDR-002');
    expect(ids).toContain('SEC-HDR-003');
    expect(ids).toContain('SEC-HDR-004');
  });

  it('detects missing HSTS on https target', async () => {
    const hstsCheck = checks.find((c) => c.rule.id === 'SEC-HDR-001')!;
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: {},
        body: 'ok',
        responseTime: 10,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/api', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const results = await hstsCheck.run(ctx);
    expect(results).toHaveLength(1);
    expect(results[0]?.ruleId).toBe('SEC-HDR-001');
  });

  it('passes when HSTS header is present', async () => {
    const hstsCheck = checks.find((c) => c.rule.id === 'SEC-HDR-001')!;
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'strict-transport-security': 'max-age=31536000' },
        body: 'ok',
        responseTime: 10,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/api', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const results = await hstsCheck.run(ctx);
    expect(results).toHaveLength(0);
  });
});

describe('Cors Checks', () => {
  it('detects wildcard Access-Control-Allow-Origin', async () => {
    const [corsCheck] = CorsChecks.getChecks();
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'access-control-allow-origin': '*' },
        body: '',
        responseTime: 5,
      }),
    };
    const ctx: any = {
      endpoint: { url: 'https://example.com/api', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const results = await corsCheck!.run(ctx);
    expect(results).toHaveLength(1);
    expect(results[0]?.ruleId).toBe('SEC-CORS-001');
  });
});

describe('Info Disclosure Checks', () => {
  it('detects Server header with version information', async () => {
    const checks = InfoDisclosureChecks.getChecks();
    const serverCheck = checks.find((c) => c.rule.id === 'SEC-HDR-005')!;
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { server: 'Apache/2.4.41 (Ubuntu)' },
        body: '',
        responseTime: 5,
      }),
    };
    const ctx: any = {
      endpoint: { url: 'https://example.com/', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const results = await serverCheck.run(ctx);
    expect(results).toHaveLength(1);
    expect(results[0]?.ruleId).toBe('SEC-HDR-005');
  });
});
