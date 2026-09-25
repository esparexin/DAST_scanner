import { describe, it, expect, vi } from 'vitest';
import { VerificationEngine } from '../verification-engine.js';
import type { PayloadVerificationRequest } from '../verification-engine.js';
import type { IPayloadDefinition, MaterializedTestVariant } from '@securityscan/payload-engine';
import { DetectionCategory } from '@securityscan/contracts';

const createMockHttpClient = (responseFn: (url: string) => any) => ({
  request: vi.fn().mockImplementation((req: any) => Promise.resolve(responseFn(req.url))),
});

const sqliPayload: IPayloadDefinition = {
  id: 'PL-SQLI-ERR-001',
  name: 'SQLi Error Probe',
  version: '1.0.0',
  status: 'ACTIVE',
  category: DetectionCategory.INJECTION,
  subcategory: 'error-based',
  description: 'Test',
  safetyLevel: 'BOUNDED_ACTIVE',
  template: { raw: "'\"", supportedTransformations: ['NONE'] },
  applicability: {
    parameterLocations: ['query'],
    parameterTypes: ['string'],
    targetContexts: ['ANY'],
    protocols: ['HTTP'],
  },
  detection: {
    strategy: 'ERROR_SIGNATURE',
    errorSignatures: ['you have an error in your sql syntax'],
  },
  verification: {
    strategy: 'REPLAY_PROBE_CONFIRMATION',
    replayAttemptsRequired: 2,
  },
  references: { cwe: ['CWE-89'], owaspTop10: ['A03:2021'], owaspApiSecurity: [] },
  remediation: { concept: 'Parameterize', guidance: 'Use prepared statements' },
};

const xssPayload: IPayloadDefinition = {
  id: 'PL-XSS-TAG-001',
  name: 'XSS Tag Canary',
  version: '1.0.0',
  status: 'ACTIVE',
  category: DetectionCategory.XSS,
  subcategory: 'reflected',
  description: 'Test',
  safetyLevel: 'BOUNDED_ACTIVE',
  template: { raw: '<canary123>', canaryPrefix: 'canary', supportedTransformations: ['NONE'] },
  applicability: {
    parameterLocations: ['query'],
    parameterTypes: ['string'],
    targetContexts: ['ANY'],
    protocols: ['HTTP'],
  },
  detection: { strategy: 'CANARY_REFLECTION' },
  verification: {
    strategy: 'TOKEN_EQUIVALENCE',
    replayAttemptsRequired: 1,
  },
  references: { cwe: ['CWE-79'], owaspTop10: ['A03:2021'], owaspApiSecurity: [] },
  remediation: { concept: 'Encode', guidance: 'HTML entity encoding' },
};

const jwtPayload: IPayloadDefinition = {
  id: 'PL-AUTH-JWT-001',
  name: 'JWT None Alg',
  version: '1.0.0',
  status: 'ACTIVE',
  category: DetectionCategory.AUTHENTICATION,
  subcategory: 'jwt',
  description: 'Test',
  safetyLevel: 'SAFE',
  template: { raw: 'eyJhbGciOiJub25lIn0.test.', supportedTransformations: ['NONE'] },
  applicability: {
    parameterLocations: ['header'],
    parameterTypes: ['string'],
    targetContexts: ['HEADER_VALUE'],
    protocols: ['HTTP'],
  },
  detection: {
    strategy: 'DIFFERENTIAL_STATUS',
    expectedStatusCodes: [200],
  },
  verification: {
    strategy: 'STATUS_CODE_STABILITY',
    replayAttemptsRequired: 2,
  },
  references: { cwe: ['CWE-287'], owaspTop10: ['A07:2021'], owaspApiSecurity: ['API2:2023'] },
  remediation: { concept: 'Verify signatures', guidance: 'Reject alg:none' },
};

const makeVariant = (payloadId: string, canaryToken?: string): MaterializedTestVariant => ({
  payloadId,
  transformation: 'NONE',
  canaryToken,
  finalValue: canaryToken ? `<${canaryToken}>` : "'\"",
  description: 'Test variant',
});

describe('VerificationEngine - Payload-Aware Strategies', () => {
  it('REPLAY_PROBE_CONFIRMATION: confirms SQLi when error signature reproduced', async () => {
    const httpClient = createMockHttpClient(() => ({
      statusCode: 500,
      headers: { 'content-type': 'text/html' },
      body: "Error: you have an error in your sql syntax near '\"'",
      responseTime: 10,
    }));

    const engine = new VerificationEngine(httpClient as any);
    const result = await engine.verifyWithPayload({
      findingId: 'F-001',
      endpoint: 'http://localhost:9999/search?q=test',
      method: 'GET',
      parameter: 'q',
      payloadDefinition: sqliPayload,
      variant: makeVariant('PL-SQLI-ERR-001'),
    });

    expect(result.verified).toBe(true);
    expect(result.confidence).toBe('CONFIRMED');
    expect(result.strategy).toBe('REPLAY_PROBE_CONFIRMATION');
    expect(result.replayCount).toBe(2);
  });

  it('REPLAY_PROBE_CONFIRMATION: rejects when error signature absent', async () => {
    const httpClient = createMockHttpClient(() => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      body: 'All fine here',
      responseTime: 10,
    }));

    const engine = new VerificationEngine(httpClient as any);
    const result = await engine.verifyWithPayload({
      findingId: 'F-002',
      endpoint: 'http://localhost:9999/search?q=test',
      method: 'GET',
      parameter: 'q',
      payloadDefinition: sqliPayload,
      variant: makeVariant('PL-SQLI-ERR-001'),
    });

    expect(result.verified).toBe(false);
    expect(result.confidence).toBe('LOW');
  });

  it('TOKEN_EQUIVALENCE: confirms XSS when canary token reflected', async () => {
    const httpClient = createMockHttpClient(() => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      body: '<html>Results: <canary123></html>',
      responseTime: 10,
    }));

    const engine = new VerificationEngine(httpClient as any);
    const result = await engine.verifyWithPayload({
      findingId: 'F-003',
      endpoint: 'http://localhost:9999/search?q=test',
      method: 'GET',
      parameter: 'q',
      payloadDefinition: xssPayload,
      variant: makeVariant('PL-XSS-TAG-001', 'canary123'),
    });

    expect(result.verified).toBe(true);
    expect(result.confidence).toBe('CONFIRMED');
    expect(result.strategy).toBe('TOKEN_EQUIVALENCE');
  });

  it('TOKEN_EQUIVALENCE: rejects when canary not reflected', async () => {
    const httpClient = createMockHttpClient(() => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      body: '<html>Results: &lt;canary123&gt;</html>',
      responseTime: 10,
    }));

    const engine = new VerificationEngine(httpClient as any);
    const result = await engine.verifyWithPayload({
      findingId: 'F-004',
      endpoint: 'http://localhost:9999/search?q=test',
      method: 'GET',
      parameter: 'q',
      payloadDefinition: xssPayload,
      variant: makeVariant('PL-XSS-TAG-001', 'canary123'),
    });

    expect(result.verified).toBe(false);
  });

  it('STATUS_CODE_STABILITY: confirms JWT bypass when 200 consistently returned', async () => {
    const httpClient = createMockHttpClient(() => ({
      statusCode: 200,
      headers: {},
      body: '{"user": "admin"}',
      responseTime: 10,
    }));

    const engine = new VerificationEngine(httpClient as any);
    const result = await engine.verifyWithPayload({
      findingId: 'F-005',
      endpoint: 'http://localhost:9999/api/me?token=x',
      method: 'GET',
      parameter: 'token',
      payloadDefinition: jwtPayload,
      variant: makeVariant('PL-AUTH-JWT-001'),
    });

    expect(result.verified).toBe(true);
    expect(result.confidence).toBe('CONFIRMED');
    expect(result.strategy).toBe('STATUS_CODE_STABILITY');
  });

  it('STATUS_CODE_STABILITY: rejects when 401 returned', async () => {
    const httpClient = createMockHttpClient(() => ({
      statusCode: 401,
      headers: {},
      body: '{"error": "unauthorized"}',
      responseTime: 10,
    }));

    const engine = new VerificationEngine(httpClient as any);
    const result = await engine.verifyWithPayload({
      findingId: 'F-006',
      endpoint: 'http://localhost:9999/api/me?token=x',
      method: 'GET',
      parameter: 'token',
      payloadDefinition: jwtPayload,
      variant: makeVariant('PL-AUTH-JWT-001'),
    });

    expect(result.verified).toBe(false);
    expect(result.confidence).toBe('LOW');
  });

  it('legacy verify still works for backward compatibility', async () => {
    const httpClient = createMockHttpClient(() => ({
      statusCode: 200,
      headers: {},
      body: 'ok',
      responseTime: 5,
    }));

    const engine = new VerificationEngine(httpClient as any);
    const result = await engine.verify({
      findingId: 'F-LEGACY',
      endpoint: 'http://localhost:9999/test',
      method: 'GET',
    });

    expect(result.verified).toBe(true);
    expect(result.strategy).toBe('LEGACY_REPLAY');
  });
});
