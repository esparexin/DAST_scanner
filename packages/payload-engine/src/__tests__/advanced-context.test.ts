import { describe, it, expect, vi } from 'vitest';
import {
  CanaryGenerator,
  OpenApiParameterAdapter,
  ReflectionContextAnalyzer,
  MutationPipeline,
  type IPayloadDefinition,
} from '../index.js';
import { DetectionCategory } from '@securityscan/contracts';

describe('CanaryGenerator', () => {
  it('generates random alphanumeric canary tokens with prefix', () => {
    const canary = CanaryGenerator.generate('testcanary', 'ALPHANUMERIC');
    expect(canary.token.startsWith('testcanary')).toBe(true);
    expect(canary.token.length).toBeGreaterThan(12);
  });

  it('generates TAG_NAME canary enclosed in angle brackets', () => {
    const canary = CanaryGenerator.generate('xsstag', 'TAG_NAME');
    expect(canary.patternToObserve).toBe(`<${canary.token}>`);
  });

  it('generates collision-resistant nonces', () => {
    const c1 = CanaryGenerator.generate('c');
    const c2 = CanaryGenerator.generate('c');
    expect(c1.token).not.toBe(c2.token);
  });
});

describe('OpenApiParameterAdapter', () => {
  const mockEndpoint: any = {
    path: '/users/{id}',
    parameters: [
      { name: 'id', location: 'path', required: true, type: 'integer' },
      { name: 'avatar', location: 'body', required: false, type: 'file' },
      { name: 'filter', location: 'query', required: false, type: 'string' },
    ],
  };

  it('infers integer constraints and suggests SQLi category', () => {
    const constraint = OpenApiParameterAdapter.mapSchemaToConstraints(mockEndpoint, 'id');
    expect(constraint.inferredType).toBe('integer');
    expect(constraint.isNumeric).toBe(true);
    expect(constraint.suggestedCategories).toContain('INJECTION');
  });

  it('infers file constraints and suggests Path Traversal / Upload', () => {
    const constraint = OpenApiParameterAdapter.mapSchemaToConstraints(mockEndpoint, 'avatar');
    expect(constraint.inferredType).toBe('file');
    expect(constraint.suggestedCategories).toContain('PATH_TRAVERSAL');
  });
});

describe('ReflectionContextAnalyzer', () => {
  it('detects HTML_BODY reflection context', async () => {
    const mockHttpClient = {
      request: vi.fn().mockImplementation((req) => {
        const u = new URL(req.url);
        const q = u.searchParams.get('q') ?? '';
        return Promise.resolve({
          statusCode: 200,
          headers: { 'content-type': 'text/html' },
          body: `<html><body><h1>Search Results</h1><p>You searched for: ${q}</p></body></html>`,
          responseTime: 10,
        });
      }),
    };

    const analyzer = new ReflectionContextAnalyzer(mockHttpClient as any);
    const result = await analyzer.analyzeReflection('https://example.com/search', 'q');
    expect(result.reflected).toBe(true);
    expect(result.context).toBe('HTML_BODY');
  });

  it('detects HTML_ATTRIBUTE reflection context', async () => {
    const mockHttpClient = {
      request: vi.fn().mockImplementation((req) => {
        const u = new URL(req.url);
        const q = u.searchParams.get('q') ?? '';
        return Promise.resolve({
          statusCode: 200,
          headers: { 'content-type': 'text/html' },
          body: `<html><body><input type="text" name="search" value="${q}"></body></html>`,
          responseTime: 10,
        });
      }),
    };

    const analyzer = new ReflectionContextAnalyzer(mockHttpClient as any);
    const result = await analyzer.analyzeReflection('https://example.com/search', 'q');
    expect(result.reflected).toBe(true);
    expect(result.context).toBe('HTML_ATTRIBUTE');
  });

  it('detects non-reflecting parameters', async () => {
    const mockHttpClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        body: '<html><body>Welcome!</body></html>',
        responseTime: 10,
      }),
    };

    const analyzer = new ReflectionContextAnalyzer(mockHttpClient as any);
    const result = await analyzer.analyzeReflection('https://example.com/profile', 'id');
    expect(result.reflected).toBe(false);
  });
});

describe('HTTP Parameter Pollution (HPP) in MutationPipeline', () => {
  const sampleHppPayload: IPayloadDefinition = {
    id: 'PL-HPP-001',
    name: 'HPP Parameter Injection Probe',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'hpp',
    description: 'Generates duplicate query parameters to evaluate parameter precedence.',
    safetyLevel: 'SAFE',
    template: {
      raw: 'canary_val',
      supportedTransformations: ['HPP_POLLUTION'],
    },
    applicability: {
      parameterLocations: ['query'],
      parameterTypes: ['string'],
      targetContexts: ['ANY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'CANARY_REFLECTION',
    },
    verification: {
      strategy: 'TOKEN_EQUIVALENCE',
      replayAttemptsRequired: 1,
    },
    references: {
      cwe: ['CWE-20'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-INPV-04'],
      asvs: ['V5.1.1'],
    },
    remediation: {
      concept: 'Enforce strict single-parameter parsing.',
      guidance: 'Reject requests with duplicate query parameters in reverse proxy or application router.',
      defenseInDepth: ['Configure web application framework to accept first or last occurrence deterministically.'],
    },
  };

  it('generates duplicate key and array notation variants', () => {
    const pipeline = new MutationPipeline();
    const variants = pipeline.materialize(sampleHppPayload, 'id', '1');
    expect(variants.length).toBeGreaterThanOrEqual(3); // Raw, Duplicate Key, Array Notation

    const dupKey = variants.find((v) => v.description.includes('Duplicate Key'));
    expect(dupKey?.isHppVariant).toBe(true);
    expect(dupKey?.hppKey).toBe('id');

    const arrKey = variants.find((v) => v.description.includes('Array Notation'));
    expect(arrKey?.isHppVariant).toBe(true);
    expect(arrKey?.hppKey).toBe('id[]');
  });
});
