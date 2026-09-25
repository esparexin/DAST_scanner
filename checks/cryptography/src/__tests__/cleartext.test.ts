import { describe, it, expect } from 'vitest';
import { CleartextChecks } from '../cleartext-check.js';
import { HttpMethod } from '@securityscan/contracts';

describe('CleartextChecks', () => {
  const [check] = CleartextChecks.getChecks();

  it('flags unencrypted remote http:// URL', async () => {
    const ctx: any = {
      endpoint: { url: 'http://api.production.corp/login', method: HttpMethod.POST },
      httpClient: { request: () => {} },
    };
    const findings = await check!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-CRYPTO-001');
  });

  it('ignores localhost unencrypted for development testing', async () => {
    const ctx: any = {
      endpoint: { url: 'http://localhost:3000/login', method: HttpMethod.POST },
      httpClient: { request: () => {} },
    };
    const findings = await check!.run(ctx);
    expect(findings).toHaveLength(0);
  });
});
