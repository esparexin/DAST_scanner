import { describe, it, expect, vi } from 'vitest';
import {
  PayloadRegistry,
  PayloadSelector,
  MutationPipeline,
  PayloadTestExecutor,
  type IPayloadDefinition,
} from '../index.js';
import { DetectionCategory, ScanProfile, HttpMethod } from '@securityscan/contracts';

const sampleSqliPayload: IPayloadDefinition = {
  id: 'PL-SQLI-001',
  name: 'Syntax Quote Disruption',
  version: '1.0.0',
  status: 'ACTIVE',
  category: DetectionCategory.INJECTION,
  subcategory: 'syntax',
  description: 'Probes for SQL syntax error leakage using quote marks.',
  safetyLevel: 'BOUNDED_ACTIVE',
  template: {
    raw: "'\"",
    supportedTransformations: ['URL_ENCODE', 'DOUBLE_URL_ENCODE'],
  },
  applicability: {
    parameterLocations: ['query', 'body'],
    parameterTypes: ['string', 'integer'],
    targetContexts: ['ANY', 'SQL_CLAUSE'],
    protocols: ['HTTP', 'HTTPS'],
  },
  detection: {
    strategy: 'ERROR_SIGNATURE',
    errorSignatures: ['syntax error', 'mysql_fetch'],
  },
  verification: {
    strategy: 'REPLAY_PROBE_CONFIRMATION',
    replayAttemptsRequired: 2,
  },
  references: {
    cwe: ['CWE-89'],
    owaspTop10: ['A03:2021'],
    owaspApiSecurity: ['API8:2023'],
    wstg: ['WSTG-INPV-05'],
    asvs: ['V5.3.4'],
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssScore: 9.8,
  },
  remediation: {
    concept: 'Parameterized queries',
    guidance: 'Enforce prepared statements across all database connectors.',
    defenseInDepth: ['Disable verbose database error dumps in production.'],
  },
};

const sampleXssPayload: IPayloadDefinition = {
  id: 'PL-XSS-001',
  name: 'Random Tag Canary Reflection',
  version: '1.0.0',
  status: 'ACTIVE',
  category: DetectionCategory.XSS,
  subcategory: 'reflected',
  description: 'Injects safe alphanumeric tag canary to detect unescaped HTML reflection.',
  safetyLevel: 'BOUNDED_ACTIVE',
  template: {
    raw: '<{{CANARY}}>',
    canaryPrefix: 'xsscanary',
    defaultCanaryType: 'RANDOM_TAG',
    supportedTransformations: ['URL_ENCODE', 'HTML_ENTITY'],
  },
  applicability: {
    parameterLocations: ['query', 'path'],
    parameterTypes: ['string'],
    targetContexts: ['HTML_BODY'],
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
    cwe: ['CWE-79'],
    owaspTop10: ['A03:2021'],
    owaspApiSecurity: [],
    wstg: ['WSTG-INPV-01'],
    asvs: ['V5.3.1'],
  },
  remediation: {
    concept: 'Contextual output encoding',
    guidance: 'HTML-entity encode user input reflected into markup.',
    defenseInDepth: ['Enforce Content-Security-Policy with frame-ancestors.'],
  },
};

describe('Payload Engine Foundation', () => {
  const registry = new PayloadRegistry();
  registry.register(sampleSqliPayload);
  registry.register(sampleXssPayload);

  describe('Context Index & Multi-Dimensional Lookup', () => {
    it('indexes payloads by ID, category, and parameter type', () => {
      expect(registry.get('PL-SQLI-001')).toBeDefined();
      expect(registry.getActive()).toHaveLength(2);

      const index = registry.getIndex();
      const sqliIds = index.queryCandidateIds({ category: DetectionCategory.INJECTION });
      expect(sqliIds.has('PL-SQLI-001')).toBe(true);
      expect(sqliIds.has('PL-XSS-001')).toBe(false);
    });

    it('answers whether a payload is appropriate for a parameter context', () => {
      const selector = new PayloadSelector(registry);

      // Integer parameter in query string for WEB_STANDARD profile
      const intQueryCandidates = selector.select({
        name: 'userId',
        location: 'query',
        type: 'integer',
        scanProfile: ScanProfile.WEB_STANDARD,
      });

      // SQLi allows integer; XSS only applies to string
      expect(intQueryCandidates.some((p) => p.id === 'PL-SQLI-001')).toBe(true);
      expect(intQueryCandidates.some((p) => p.id === 'PL-XSS-001')).toBe(false);
    });

    it('respects safety level limits by scan profile', () => {
      const selector = new PayloadSelector(registry);

      // PASSIVE profile must not select BOUNDED_ACTIVE payloads
      const passiveCandidates = selector.select({
        name: 'q',
        location: 'query',
        type: 'string',
        scanProfile: ScanProfile.PASSIVE,
      });
      expect(passiveCandidates).toHaveLength(0);
    });
  });

  describe('Mutation Pipeline', () => {
    const pipeline = new MutationPipeline();

    it('generates raw and transformed variants without duplicate stored strings', () => {
      const variants = pipeline.materialize(sampleSqliPayload, 'id', '12', ['URL_ENCODE']);
      expect(variants).toHaveLength(2); // Raw + URL_ENCODE

      expect(variants[0]?.transformation).toBe('NONE');
      expect(variants[0]?.finalValue).toBe("'\"");

      expect(variants[1]?.transformation).toBe('URL_ENCODE');
      expect(variants[1]?.finalValue).toBe('%27%22');
    });

    it('substitutes benign random canary tokens deterministically', () => {
      const variants = pipeline.materialize(sampleXssPayload, 'search', 'hello');
      expect(variants.length).toBeGreaterThanOrEqual(1);
      const first = variants[0]!;
      expect(first.canaryToken).toBeDefined();
      expect(first.canaryToken?.startsWith('xsscanary')).toBe(true);
      expect(first.finalValue).toBe(`<${first.canaryToken}>`);
    });
  });

  describe('Test Executor & Scope/Rate-Limit Gate Integration', () => {
    it('executes variant strictly through SecureHttpClient and checks canary reflection', async () => {
      const pipeline = new MutationPipeline();
      const [xssVariant] = pipeline.materialize(sampleXssPayload, 'q', 'test');

      const mockHttpClient = {
        request: vi.fn().mockImplementation((req) => {
          const url = new URL(req.url);
          const q = url.searchParams.get('q') ?? '';
          return Promise.resolve({
            statusCode: 200,
            headers: { 'content-type': 'text/html' },
            body: `<html><body>Search: ${q}</body></html>`,
            responseTime: 22,
          });
        }),
      };

      const executor = new PayloadTestExecutor(mockHttpClient as any);
      const result = await executor.executeVariantOnUrlParam(
        'https://example.com/search',
        'q',
        xssVariant!,
        HttpMethod.GET,
      );

      expect(result.statusCode).toBe(200);
      expect(result.canaryObserved).toBe(true);
      expect(mockHttpClient.request).toHaveBeenCalledTimes(1);
    });
  });
});
