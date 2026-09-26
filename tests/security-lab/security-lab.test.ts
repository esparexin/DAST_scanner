import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { ScopeValidator } from '@securityscan/scope';
import { SecureHttpClient } from '@securityscan/http-client';
import { DetectionEngine, type SecurityCheck, type CheckContext } from '@securityscan/detection-engine';
import {
  DetectionCategory,
  DetectionType,
  Severity,
  Confidence,
  HttpMethod,
} from '@securityscan/contracts';
import {
  PayloadRegistry,
  PayloadSelector,
  MutationPipeline,
  PayloadTestExecutor,
  loadDefaultCatalogs,
  CatalogSigner,
  CatalogOverrideManager,
} from '@securityscan/payload-engine';
import { VerificationEngine } from '@securityscan/verification-engine';

let vulnerableServer: Server;
let safeServer: Server;
let xssServer: Server;
let vulnPort: number;
let safePort: number;
let xssPort: number;

beforeAll(async () => {
  // SQLi-vulnerable server
  vulnerableServer = createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost`);
    const q = url.searchParams.get('q') ?? '';
    if (url.pathname === '/search') {
      if (q.includes("'") || q.includes('"')) {
        res.writeHead(500, { 'content-type': 'text/html' });
        res.end(`Error: you have an error in your sql syntax near '${q}'`);
      } else {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(`<html><body>Results for: ${q}</body></html>`);
      }
    } else {
      res.writeHead(200);
      res.end('ok');
    }
  });

  // Hardened safe server
  safeServer = createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
    });
    res.end('<html><body>Safe response</body></html>');
  });

  // XSS-vulnerable server (reflects input without encoding)
  xssServer = createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost`);
    const q = url.searchParams.get('q') ?? '';
    if (url.pathname === '/reflect') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<html><body><p>You searched for: ${q}</p></body></html>`);
    } else {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><body>Home</body></html>');
    }
  });

  await new Promise<void>((resolve) => vulnerableServer.listen(0, () => resolve()));
  await new Promise<void>((resolve) => safeServer.listen(0, () => resolve()));
  await new Promise<void>((resolve) => xssServer.listen(0, () => resolve()));

  const vulnAddr = vulnerableServer.address();
  const safeAddr = safeServer.address();
  const xssAddr = xssServer.address();
  vulnPort = typeof vulnAddr === 'object' && vulnAddr ? vulnAddr.port : 0;
  safePort = typeof safeAddr === 'object' && safeAddr ? safeAddr.port : 0;
  xssPort = typeof xssAddr === 'object' && xssAddr ? xssAddr.port : 0;
});

afterAll(() => {
  vulnerableServer?.close();
  safeServer?.close();
  xssServer?.close();
});

// ─── Regression Suite ───────────────────────────────────────────────

describe('Security Lab E2E', () => {
  it('detects SQL injection on vulnerable server', async () => {
    const scope = new ScopeValidator([`http://localhost:${vulnPort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const engine = new DetectionEngine();

    const sqliCheck: SecurityCheck = {
      rule: {
        id: 'SEC-SQLI-001',
        name: 'SQL Injection',
        description: 'Detects SQL injection via error-based detection',
        category: DetectionCategory.INJECTION,
        type: DetectionType.ACTIVE,
        severity: Severity.CRITICAL,
        confidence: Confidence.CONFIRMED,
        owasp: ['A03:2021'],
        cwe: ['CWE-89'],
        remediation: 'Use parameterized queries',
        references: [],
        enabled: true,
        tags: ['sqli'],
      },
      async run(ctx: CheckContext) {
        const testUrl = new URL(ctx.endpoint.url);
        for (const [key] of testUrl.searchParams.entries()) {
          testUrl.searchParams.set(key, "' OR 1=1--");
          try {
            const res = await ctx.httpClient.request({
              method: HttpMethod.GET,
              url: testUrl.toString(),
            });
            if (
              res.body.toLowerCase().includes('error in your sql syntax') ||
              res.body.toLowerCase().includes('syntax error')
            ) {
              return [
                {
                  ruleId: 'SEC-SQLI-001',
                  title: 'SQL Injection Found',
                  description: `SQL error detected in parameter ${key}`,
                  severity: Severity.CRITICAL,
                  confidence: Confidence.CONFIRMED,
                  category: DetectionCategory.INJECTION,
                  endpoint: ctx.endpoint.url,
                  method: 'GET',
                  parameter: key,
                  evidence: {
                    request: { method: 'GET', url: testUrl.toString(), headers: {} },
                    response: {
                      statusCode: res.statusCode,
                      headers: res.headers,
                      body: res.body.slice(0, 500),
                      responseTime: res.responseTime,
                    },
                  },
                },
              ];
            }
          } catch {
            // continue
          }
        }
        return [];
      },
    };

    engine.registerCheck(sqliCheck);

    const results = await engine.run({
      endpoint: {
        url: `http://localhost:${vulnPort}/search?q=test`,
        method: HttpMethod.GET,
      },
      httpClient,
    });

    expect(results.length).toBeGreaterThan(0);
    expect(results[0].ruleId).toBe('SEC-SQLI-001');
    expect(results[0].severity).toBe(Severity.CRITICAL);
  });

  it('reports zero findings on hardened server', async () => {
    const scope = new ScopeValidator([`http://localhost:${safePort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const engine = new DetectionEngine();

    const sqliCheck: SecurityCheck = {
      rule: {
        id: 'SEC-SQLI-001',
        name: 'SQL Injection',
        description: 'Detects SQL injection',
        category: DetectionCategory.INJECTION,
        type: DetectionType.ACTIVE,
        severity: Severity.CRITICAL,
        confidence: Confidence.CONFIRMED,
        owasp: ['A03:2021'],
        cwe: ['CWE-89'],
        remediation: 'Use parameterized queries',
        references: [],
        enabled: true,
        tags: ['sqli'],
      },
      async run(ctx: CheckContext) {
        const testUrl = new URL(ctx.endpoint.url);
        for (const [key] of testUrl.searchParams.entries()) {
          testUrl.searchParams.set(key, "' OR 1=1--");
          try {
            const res = await ctx.httpClient.request({
              method: HttpMethod.GET,
              url: testUrl.toString(),
            });
            if (res.body.toLowerCase().includes('error in your sql syntax')) {
              return [
                {
                  ruleId: 'SEC-SQLI-001',
                  title: 'SQL Injection Found',
                  description: 'SQL error detected',
                  severity: Severity.CRITICAL,
                  confidence: Confidence.CONFIRMED,
                  category: DetectionCategory.INJECTION,
                  endpoint: ctx.endpoint.url,
                  method: 'GET',
                  evidence: {
                    request: { method: 'GET', url: testUrl.toString(), headers: {} },
                    response: {
                      statusCode: res.statusCode,
                      headers: res.headers,
                      body: res.body.slice(0, 500),
                      responseTime: res.responseTime,
                    },
                  },
                },
              ];
            }
          } catch {
            // continue
          }
        }
        return [];
      },
    };

    engine.registerCheck(sqliCheck);

    const results = await engine.run({
      endpoint: {
        url: `http://localhost:${safePort}/search?q=test`,
        method: HttpMethod.GET,
      },
      httpClient,
    });

    expect(results.length).toBe(0);
  });
});

// ─── Payload Engine Regression Suite ────────────────────────────────

describe('Payload Engine Regression: SQLi Detection', () => {
  it('detects SQLi using PayloadSelector + MutationPipeline + PayloadTestExecutor', async () => {
    const scope = new ScopeValidator([`http://localhost:${vulnPort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();
    const executor = new PayloadTestExecutor(httpClient);

    const payloads = selector.select({
      name: 'q',
      location: 'query',
      type: 'string',
      category: DetectionCategory.INJECTION,
    });

    expect(payloads.length).toBeGreaterThan(0);

    let detected = false;
    for (const payload of payloads) {
      const variants = pipeline.materialize(payload, 'q', 'test');
      for (const variant of variants) {
        const result = await executor.executeVariantOnUrlParam(
          `http://localhost:${vulnPort}/search?q=test`,
          'q',
          variant,
          HttpMethod.GET,
        );

        const sigs = payload.detection.errorSignatures ?? [];
        for (const sig of sigs) {
          if (result.responseBodySnippet.toLowerCase().includes(sig.toLowerCase())) {
            detected = true;
          }
        }
      }
    }

    expect(detected).toBe(true);
  });

  it('produces zero false positives on hardened server', async () => {
    const scope = new ScopeValidator([`http://localhost:${safePort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();
    const executor = new PayloadTestExecutor(httpClient);

    const payloads = selector.select({
      name: 'q',
      location: 'query',
      type: 'string',
      category: DetectionCategory.INJECTION,
    });

    for (const payload of payloads) {
      const variants = pipeline.materialize(payload, 'q', 'test');
      for (const variant of variants) {
        const result = await executor.executeVariantOnUrlParam(
          `http://localhost:${safePort}/search?q=test`,
          'q',
          variant,
          HttpMethod.GET,
        );

        const sigs = payload.detection.errorSignatures ?? [];
        for (const sig of sigs) {
          expect(result.responseBodySnippet.toLowerCase()).not.toContain(sig.toLowerCase());
        }
      }
    }
  });
});

describe('Payload Engine Regression: XSS Detection', () => {
  it('detects reflected XSS via canary reflection', async () => {
    const scope = new ScopeValidator([`http://localhost:${xssPort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();
    const executor = new PayloadTestExecutor(httpClient);

    const payloads = selector.select({
      name: 'q',
      location: 'query',
      type: 'string',
      category: DetectionCategory.XSS,
    });

    expect(payloads.length).toBeGreaterThan(0);

    let detected = false;
    for (const payload of payloads) {
      const variants = pipeline.materialize(payload, 'q', 'test');
      for (const variant of variants) {
        const result = await executor.executeVariantOnUrlParam(
          `http://localhost:${xssPort}/reflect?q=test`,
          'q',
          variant,
          HttpMethod.GET,
        );

        if (result.canaryObserved) {
          detected = true;
        }
      }
    }

    expect(detected).toBe(true);
  });

  it('XSS canary not observed on safe server', async () => {
    const scope = new ScopeValidator([`http://localhost:${safePort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();
    const executor = new PayloadTestExecutor(httpClient);

    const payloads = selector.select({
      name: 'q',
      location: 'query',
      type: 'string',
      category: DetectionCategory.XSS,
    });

    for (const payload of payloads) {
      const variants = pipeline.materialize(payload, 'q', 'test');
      for (const variant of variants) {
        const result = await executor.executeVariantOnUrlParam(
          `http://localhost:${safePort}/search?q=test`,
          'q',
          variant,
          HttpMethod.GET,
        );

        expect(result.canaryObserved).toBe(false);
      }
    }
  });
});

describe('Payload Engine Regression: Verification Engine', () => {
  it('confirms SQLi finding via REPLAY_PROBE_CONFIRMATION', async () => {
    const scope = new ScopeValidator([`http://localhost:${vulnPort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();
    const verificationEngine = new VerificationEngine(httpClient);

    const sqliPayloads = selector.select({
      name: 'q',
      location: 'query',
      type: 'string',
      category: DetectionCategory.INJECTION,
    });

    const payload = sqliPayloads[0];
    const variants = pipeline.materialize(payload, 'q', 'test');
    const variant = variants[0]; // Raw variant

    const result = await verificationEngine.verifyWithPayload({
      findingId: 'F-REGRESSION-001',
      endpoint: `http://localhost:${vulnPort}/search?q=test`,
      method: 'GET',
      parameter: 'q',
      payloadDefinition: payload,
      variant,
    });

    expect(result.verified).toBe(true);
    expect(result.confidence).toBe('CONFIRMED');
    expect(result.strategy).toBe('REPLAY_PROBE_CONFIRMATION');
  });

  it('rejects verification on safe server', async () => {
    const scope = new ScopeValidator([`http://localhost:${safePort}/*`]);
    const httpClient = new SecureHttpClient(scope);
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();
    const verificationEngine = new VerificationEngine(httpClient);

    const sqliPayloads = selector.select({
      name: 'q',
      location: 'query',
      type: 'string',
      category: DetectionCategory.INJECTION,
    });

    const payload = sqliPayloads[0];
    const variants = pipeline.materialize(payload, 'q', 'test');
    const variant = variants[0];

    const result = await verificationEngine.verifyWithPayload({
      findingId: 'F-REGRESSION-002',
      endpoint: `http://localhost:${safePort}/search?q=test`,
      method: 'GET',
      parameter: 'q',
      payloadDefinition: payload,
      variant,
    });

    expect(result.verified).toBe(false);
    expect(result.confidence).toBe('LOW');
  });
});

describe('Catalog Integrity Regression', () => {
  it('default catalogs pass signature verification', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);
    const allPayloads = registry.getAll();

    const keys = CatalogSigner.generateKeyPair();
    const manifest = CatalogSigner.signCatalog(allPayloads, '1.1.0', keys.privateKey);
    const valid = CatalogSigner.verifyCatalog(manifest, allPayloads, keys.publicKey);

    expect(valid).toBe(true);
    expect(manifest.payloadCount).toBe(allPayloads.length);
  });

  it('production-safe overrides leave only SAFE payloads active', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    CatalogOverrideManager.applyOverrides(
      registry,
      CatalogOverrideManager.productionSafeOverrides(),
    );

    const active = registry.getAll().filter((p) => p.status === 'ACTIVE');
    for (const p of active) {
      expect(p.safetyLevel).toBe('SAFE');
    }
  });

  it('payload count matches expected baseline count', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);
    // 2 SQLi + 2 XSS + 1 Traversal + 1 Auth + 2 NoSQL + 2 SSTI + 2 XXE = 12 baseline payloads
    expect(registry.size()).toBe(12);
  });
});
