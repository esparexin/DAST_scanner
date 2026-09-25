import { describe, it, expect, vi } from 'vitest';
import { MassAssignmentChecks } from '../mass-assignment-check.js';
import { HttpMethod } from '@securityscan/contracts';

describe('MassAssignmentChecks', () => {
  const [check] = MassAssignmentChecks.getChecks();

  it('detects injected admin role reflected in API response', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id: 10, username: 'test', role: 'admin' }),
      }),
    };
    const ctx: any = {
      endpoint: { url: 'https://example.com/api/users', method: HttpMethod.POST },
      httpClient: mockClient,
    };
    const findings = await check!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-API-003-MASS');
  });
});
