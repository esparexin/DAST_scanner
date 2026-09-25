import { describe, it, expect, vi } from 'vitest';
import { PathTraversalChecks } from '../index.js';
import { HttpMethod } from '@securityscan/contracts';

describe('PathTraversalChecks', () => {
  const [ptCheck] = PathTraversalChecks.getChecks();

  it('detects Unix passwd file disclosure from traversal probe', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'text/plain' },
        body: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
        responseTime: 20,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/download?file=receipt.pdf', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const findings = await ptCheck!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-PT-001');
    expect(findings[0]?.parameter).toBe('file');
  });
});
