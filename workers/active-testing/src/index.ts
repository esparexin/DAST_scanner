import { ScanModel, TargetModel, EndpointModel, FindingModel } from '@securityscan/database';
import { ScanStatus, HttpMethod } from '@securityscan/contracts';
import { ScopeGuard } from '@securityscan/scope';
import { SecureHttpClient, RateLimiter } from '@securityscan/http-client';
import { DetectionEngine } from '@securityscan/detection-engine';
import { FindingEngine } from '@securityscan/finding-engine';
import { SecurityKnowledgeBase } from '@securityscan/knowledge-base';
import { SqlInjectionChecks } from '@securityscan/check-injection';
import { XssChecks } from '@securityscan/check-xss';
import { PathTraversalChecks } from '@securityscan/check-path-traversal';
import { SsrfCandidateChecks } from '@securityscan/check-ssrf';
import { CsrfChecks } from '@securityscan/check-csrf';
import { FileUploadChecks } from '@securityscan/check-file-upload';
import { ForcedBrowsingChecks } from '@securityscan/check-access-control';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('worker-active-testing');

export async function runActiveTestingWorker(scanId: string): Promise<number> {
  const scan = await ScanModel.findById(scanId);
  if (!scan || scan.status === ScanStatus.CANCELLED) return 0;

  const target = await TargetModel.findById(scan.targetId);
  if (!target || target.authorization !== 'AUTHORIZED') return 0;

  const scopeConfig = {
    scanId: scan._id.toString(),
    targetId: target._id.toString(),
    projectId: scan.projectId.toString(),
    authorized: true,
    allowedHosts: target.scope.allowedHosts,
    excludedHosts: target.scope.excludedHosts,
    allowedPaths: target.scope.allowedPaths,
    excludedPaths: target.scope.excludedPaths,
    maxRequestsPerSecond: scan.configuration.maxRequestsPerSecond,
    maxConcurrency: scan.configuration.maxConcurrency,
    maxRequests: scan.configuration.maxRequests,
    maxCrawlDepth: scan.configuration.maxCrawlDepth,
    maxResponseSize: scan.configuration.maxResponseSize,
    maxScanDuration: scan.configuration.maxScanDuration,
    timeoutPerRequest: scan.configuration.timeoutPerRequest,
  };

  const validator = ScopeGuard.createValidator(scopeConfig);
  const rateLimiter = new RateLimiter(scopeConfig.maxRequestsPerSecond);
  const httpClient = new SecureHttpClient(validator, rateLimiter);

  const activeEngine = new DetectionEngine();
  activeEngine.registerAll(SqlInjectionChecks.getChecks());
  activeEngine.registerAll(XssChecks.getChecks());
  activeEngine.registerAll(PathTraversalChecks.getChecks());
  activeEngine.registerAll(SsrfCandidateChecks.getChecks());
  activeEngine.registerAll(CsrfChecks.getChecks());
  activeEngine.registerAll(FileUploadChecks.getChecks());
  activeEngine.registerAll(ForcedBrowsingChecks.getChecks());

  const findingEngine = new FindingEngine();
  const endpoints = await EndpointModel.find({ scanId: scan._id });
  let created = 0;

  for (const ep of endpoints) {
    const ctx = {
      scanId: scan._id.toString(),
      targetId: scan.targetId.toString(),
      projectId: scan.projectId.toString(),
      httpClient,
      endpoint: ep.toObject() as any,
      baseUrl: ep.url,
    };

    try {
      const results = await activeEngine.runAll(ctx);
      for (const res of results) {
        const mapping = SecurityKnowledgeBase.resolveMapping({
          owaspIds: res.owasp,
          owaspApiIds: res.apiOwasp,
          wstgIds: res.wstg,
          asvsIds: res.asvs,
          cweIds: res.cwe,
          cvssVector: res.cvssVector,
        });

        const norm = findingEngine.normalize({
          scanId: scan._id.toString(),
          projectId: scan.projectId.toString(),
          targetId: scan.targetId.toString(),
          ruleId: res.ruleId,
          title: res.title,
          description: res.description,
          impact: res.impact,
          severity: res.severity,
          confidence: res.confidence,
          category: res.category,
          endpoint: res.endpoint,
          method: res.method,
          parameter: res.parameter,
          remediation: res.remediation,
          cwe: res.cwe,
          owasp: res.owasp,
          apiOwasp: res.apiOwasp,
          wstg: res.wstg ?? mapping.wstg.map((w) => w.id),
          asvs: res.asvs ?? mapping.asvs.map((a) => a.id),
          cvssVector: res.cvssVector ?? mapping.cvss?.vectorString,
          cvssScore: res.cvssScore ?? mapping.cvss?.baseScore,
          references: res.references,
        });

        if (norm) {
          await FindingModel.create(norm);
          created++;
        }
      }
    } catch (err) {
      logger.debug({ endpoint: ep.url, error: (err as Error).message }, 'Active worker check error');
    }
  }

  return created;
}
