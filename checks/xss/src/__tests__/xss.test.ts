import { describe, it, expect, vi } from 'vitest';
import { XssChecks } from '../index.js';
import { HttpMethod } from '@securityscan/contracts';

describe('XssChecks', () => {
  const [xssCheck] = XssChecks.getChecks();

  it('detects unencoded reflection in HTML response', async () => {
    const mockClient = {
      request: vi.fn().mockImplementation((req) => {
        const u = new URL(req.url);
        const q = u.searchParams.get('q') ?? '';
        return Promise.resolve({
          statusCode: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
          body: `<html><body>Search result for: ${q}</body></html>`,
          responseTime: 25,
        });
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/search?q=test', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const findings = await xssCheck!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-XSS-001');
    expect(findings[0]?.parameter).toBe('q');
  });

  it('does not trigger on HTML entity encoded response', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        body: '<html><body>Search: &lt;xsscanary123&gt;</body></html>',
        responseTime: 15,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/search?q=test', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const findings = await xssCheck!.run(ctx);
    expect(findings).toHaveLength(0);
  });
});
