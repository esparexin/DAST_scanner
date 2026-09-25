import { describe, it, expect } from 'vitest';
import { PocGenerator } from '../poc-generator.js';

describe('PocGenerator', () => {
  const generator = new PocGenerator();

  it('generates a PoC with redacted credentials', () => {
    const poc = generator.generate({
      findingId: 'f1',
      title: 'Missing HSTS',
      description: 'No HSTS header',
      request: { method: 'GET', url: 'https://example.com', headers: { Authorization: 'Bearer secret' } },
      response: { statusCode: 200, headers: {}, body: 'OK', responseTime: 50 },
      expectedBehavior: 'HSTS header present',
      observedBehavior: 'HSTS header missing',
      remediation: 'Add HSTS header',
    });

    expect(poc.summary).toContain('Missing HSTS');
    expect(poc.request.headers['Authorization']).toBe('[REDACTED]');
    expect(poc.steps).toHaveLength(1);
    expect(poc.preconditions).toHaveLength(1);
  });

  it('includes additional steps', () => {
    const poc = generator.generate({
      findingId: 'f1',
      title: 'Test',
      description: 'Desc',
      request: { method: 'GET', url: 'https://example.com', headers: {} },
      response: { statusCode: 200, headers: {}, responseTime: 50 },
      expectedBehavior: 'A',
      observedBehavior: 'B',
      remediation: 'Fix',
      additionalSteps: [{ description: 'Step 2' }, { description: 'Step 3' }],
    });
    expect(poc.steps).toHaveLength(3);
    expect(poc.steps[1]!.order).toBe(2);
  });
});
