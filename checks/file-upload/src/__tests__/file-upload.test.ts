import { describe, it, expect, vi } from 'vitest';
import { FileUploadChecks } from '../file-upload-check.js';
import { HttpMethod } from '@securityscan/contracts';

describe('FileUploadChecks', () => {
  const [uploadCheck] = FileUploadChecks.getChecks();

  it('flags upload endpoint accepting double executable extensions', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({ statusCode: 200, headers: {} }),
    };
    const ctx: any = {
      endpoint: { url: 'https://example.com/api/avatar-upload', method: HttpMethod.POST },
      httpClient: mockClient,
    };
    const findings = await uploadCheck!.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('SEC-UPL-001');
  });
});
