import { ScopeValidator } from '@securityscan/scope';
import { SecureHttpClient, RateLimiter } from '@securityscan/http-client';
import { Crawler } from '@securityscan/crawler';
import { DetectionEngine } from '@securityscan/detection-engine';
import { FindingEngine } from '@securityscan/finding-engine';
import { SarifGenerator } from '@securityscan/reporting';
import { RiskClassifier } from '@securityscan/risk-engine';
import {
  SecurityHeaderChecks, CookieChecks, CorsChecks, InfoDisclosureChecks,
} from '@securityscan/check-misconfiguration';
import { SqlInjectionChecks } from '@securityscan/check-injection';
import { XssChecks } from '@securityscan/check-xss';
import { PathTraversalChecks } from '@securityscan/check-path-traversal';
import { HttpMethod, Severity, FindingStatus } from '@securityscan/contracts';

export interface CliScanOptions {
  target: string;
  profile?: string;
  failOn?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  dryRun?: boolean;
  maxRequests?: number;
  rateLimit?: number;
}

export interface CliScanResult {
  exitCode: number;
  sarifOutput: string;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  policyFailed: boolean;
}

export async function runCliScan(options: CliScanOptions): Promise<CliScanResult> {
  const targetUrl = new URL(options.target);
  const failThreshold = (options.failOn ?? 'HIGH') as Severity;

  const scopeConfig = {
    scanId: `cli-${Date.now()}`,
    targetId: 'cli-target',
    projectId: 'cli-project',
    authorized: true,
    allowedHosts: [targetUrl.hostname],
    excludedHosts: [],
    allowedPaths: [],
    excludedPaths: [],
    maxRequestsPerSecond: options.rateLimit ?? 10,
    maxConcurrency: 5,
    maxRequests: options.maxRequests ?? 200,
    maxCrawlDepth: 3,
    maxResponseSize: 10 * 1024 * 1024,
    maxScanDuration: 600,
    timeoutPerRequest: 15,
  };

  const validator = new ScopeValidator(scopeConfig);
  const sarifGen = new SarifGenerator();

  // Dry run returns early with empty SARIF
  if (options.dryRun) {
    return {
      exitCode: 0,
      sarifOutput: sarifGen.generate([], options.target),
      totalFindings: 0,
      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      policyFailed: false,
    };
  }

  const rateLimiter = new RateLimiter(scopeConfig.maxRequestsPerSecond);
  const httpClient = new SecureHttpClient(validator, rateLimiter);

  // Crawl
  const crawler = new Crawler(httpClient, 2);
  const crawlResults = await crawler.crawl(options.target);

  // Engines
  const engine = new DetectionEngine();
  engine.registerAll(SecurityHeaderChecks.getChecks());
  engine.registerAll(CookieChecks.getChecks());
  engine.registerAll(CorsChecks.getChecks());
  engine.registerAll(InfoDisclosureChecks.getChecks());
  engine.registerAll(SqlInjectionChecks.getChecks());
  engine.registerAll(XssChecks.getChecks());
  engine.registerAll(PathTraversalChecks.getChecks());

  const findingEngine = new FindingEngine();
  const collectedFindings: any[] = [];

  const endpoints = [
    { url: options.target, method: HttpMethod.GET },
    ...crawlResults.map((r) => ({ url: r.url, method: HttpMethod.GET })),
  ];

  for (const ep of endpoints) {
    const ctx = {
      scanId: scopeConfig.scanId,
      targetId: scopeConfig.targetId,
      projectId: scopeConfig.projectId,
      httpClient,
      endpoint: { id: ep.url, url: ep.url, method: ep.method } as any,
      baseUrl: options.target,
    };

    const results = await engine.runAll(ctx);
    for (const r of results) {
      const norm = findingEngine.normalize({
        scanId: scopeConfig.scanId,
        projectId: scopeConfig.projectId,
        targetId: scopeConfig.targetId,
        ruleId: r.ruleId,
        title: r.title,
        description: r.description,
        impact: r.impact,
        severity: r.severity,
        confidence: r.confidence,
        category: r.category,
        endpoint: r.endpoint,
        method: r.method,
        parameter: r.parameter,
        remediation: r.remediation,
        cwe: r.cwe,
        owasp: r.owasp,
      });
      if (norm) collectedFindings.push(norm);
    }
  }

  const riskClassifier = new RiskClassifier();
  let policyFailed = false;

  const critCount = collectedFindings.filter((f) => f.severity === Severity.CRITICAL).length;
  const highCount = collectedFindings.filter((f) => f.severity === Severity.HIGH).length;
  const medCount = collectedFindings.filter((f) => f.severity === Severity.MEDIUM).length;

  for (const f of collectedFindings) {
    if (riskClassifier.shouldFailPipeline(f.severity, f.confidence, FindingStatus.VERIFIED, failThreshold)) {
      policyFailed = true;
      break;
    }
  }

  const sarifOutput = sarifGen.generate(collectedFindings, options.target);

  return {
    exitCode: policyFailed ? 1 : 0,
    sarifOutput,
    totalFindings: collectedFindings.length,
    criticalFindings: critCount,
    highFindings: highCount,
    mediumFindings: medCount,
    policyFailed,
  };
}
