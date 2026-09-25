import { describe, it, expect, vi } from 'vitest';
import { BolaChecks, BflaChecks } from '../index.js';
import { HttpMethod } from '@securityscan/contracts';

describe('BolaChecks', () => {
  const [bolaCheck] = BolaChecks.getChecks();

  it('detects BOLA/IDOR when peer object ID returns 200 OK with data', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id: 2, owner: 'other_user', data: 'private_invoice' }),
        responseTime: 20,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://api.corp/api/invoices/1', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const findings = await bolaCheck!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-BOLA-001');
    expect(findings[0]?.endpoint).toContain('/api/invoices/2');
  });

  it('ignores endpoints without numeric object IDs', async () => {
    const ctx: any = {
      endpoint: { url: 'https://api.corp/api/invoices/recent', method: HttpMethod.GET },
      httpClient: { request: vi.fn() },
    };
    const findings = await bolaCheck!.run(ctx);
    expect(findings).toHaveLength(0);
  });
});

describe('BflaChecks', () => {
  const [bflaCheck] = BflaChecks.getChecks();

  it('detects unauthenticated access to admin routes', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ adminConsole: 'active', userCount: 500 }),
        responseTime: 15,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://api.corp/api/admin/users', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const findings = await bflaCheck!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-BFLA-001');
  });

  it('does not flag standard non-admin routes', async () => {
    const ctx: any = {
      endpoint: { url: 'https://api.corp/api/public/items', method: HttpMethod.GET },
      httpClient: { request: vi.fn() },
    };
    const findings = await bflaCheck!.run(ctx);
    expect(findings).toHaveLength(0);
  });
});
