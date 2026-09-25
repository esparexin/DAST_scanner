import { describe, it, expect } from 'vitest';
import { EvidenceCollector } from '../evidence-collector.js';

describe('EvidenceCollector', () => {
  const collector = new EvidenceCollector();

  it('redacts sensitive request headers', () => {
    const evidence = collector.collect({
      request: {
        method: 'GET',
        url: 'https://example.com',
        headers: { Authorization: 'Bearer secret', 'Content-Type': 'text/html' },
      },
      response: { statusCode: 200, headers: {}, body: 'OK', responseTime: 50 },
      endpoint: 'https://example.com',
      authContext: 'anonymous',
    });
    expect(evidence.request.headers['Authorization']).toBe('[REDACTED]');
    expect(evidence.request.headers['Content-Type']).toBe('text/html');
  });

  it('redacts sensitive body content', () => {
    const evidence = collector.collect({
      request: {
        method: 'POST',
        url: 'https://example.com/login',
        headers: {},
        body: '{"username": "admin", "password": "secret123"}',
      },
      response: { statusCode: 200, headers: {}, body: '', responseTime: 50 },
      endpoint: 'https://example.com/login',
      authContext: 'anonymous',
    });
    expect(evidence.request.body).toContain('[REDACTED]');
    expect(evidence.request.body).not.toContain('secret123');
  });

  it('extracts security-relevant headers', () => {
    const evidence = collector.collect({
      request: { method: 'GET', url: 'https://example.com', headers: {} },
      response: {
        statusCode: 200,
        headers: {
          'content-security-policy': "default-src 'self'",
          'x-powered-by': 'Express',
          'content-type': 'text/html',
        },
        body: '',
        responseTime: 50,
      },
      endpoint: 'https://example.com',
      authContext: 'anonymous',
    });
    expect(evidence.relevantHeaders['content-security-policy']).toBeDefined();
    expect(evidence.relevantHeaders['x-powered-by']).toBeDefined();
    expect(evidence.relevantHeaders['content-type']).toBeUndefined();
  });

  it('truncates large response data', () => {
    const largeBody = 'x'.repeat(100000);
    const evidence = collector.collect({
      request: { method: 'GET', url: 'https://example.com', headers: {} },
      response: { statusCode: 200, headers: {}, body: largeBody, responseTime: 50 },
      endpoint: 'https://example.com',
      authContext: 'anonymous',
    });
    expect(evidence.response.body!.length).toBeLessThanOrEqual(50000);
    expect(evidence.relevantResponseData.length).toBeLessThanOrEqual(2000);
  });
});
