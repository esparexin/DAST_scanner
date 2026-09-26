import { ScanModel, EndpointModel, FindingModel } from '@securityscan/database';
import { ScanStatus } from '@securityscan/contracts';
import { ScopeGuard } from '@securityscan/scope';
import { SecureHttpClient, RateLimiter } from '@securityscan/http-client';
import { DetectionEngine } from '@securityscan/detection-engine';
import { FindingEngine } from '@securityscan/finding-engine';
import { SecurityHeaderChecks, CookieChecks, CorsChecks, InfoDisclosureChecks } from '@securityscan/check-misconfiguration';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('worker-passive');

export async function processPassiveAnalysis(scanId: string) {
  logger.info({ scanId }, 'Starting passive analysis');

  const scan = await ScanModel.findById(scanId);
  if (!scan || scan.status === ScanStatus.CANCELLED) return;

  const { default: mongoose } = await import('mongoose');
  const TargetMdl = mongoose.model('Target');
  const target = await TargetMdl.findById(scan.targetId);
  if (!target) throw new Error('Target not found');
  const t = target.toObject() as { scope: Record<string, unknown>; authorization: string; _id: { toString(): string } };

  const scopeConfig = {
    scanId: scan._id.toString(),
    targetId: t._id.toString(),
    projectId: scan.projectId.toString(),
    authorized: t.authorization === 'AUTHORIZED',
    allowedHosts: (t.scope['allowedHosts'] as string[]) ?? [],
    excludedHosts: (t.scope['excludedHosts'] as string[]) ?? [],
    allowedPaths: (t.scope['allowedPaths'] as string[]) ?? [],
    excludedPaths: (t.scope['excludedPaths'] as string[]) ?? [],
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

  // Register passive checks
  const engine = new DetectionEngine();
  engine.registerAll(SecurityHeaderChecks.getChecks());
  engine.registerAll(CookieChecks.getChecks());
  engine.registerAll(CorsChecks.getChecks());
  engine.registerAll(InfoDisclosureChecks.getChecks());

  const findingEngine = new FindingEngine();

  await ScanModel.findByIdAndUpdate(scanId, {
    status: ScanStatus.PASSIVE_ANALYSIS,
    'progress.phase': ScanStatus.PASSIVE_ANALYSIS,
  });

  // Get discovered endpoints
  const endpoints = await EndpointModel.find({ scanId: scan._id });
  let checksExecuted = 0;
  let findingsCreated = 0;

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
      const results = await engine.runAll(ctx);
      checksExecuted += engine.getChecks().length;

      for (const result of results) {
        const normalized = findingEngine.normalize({
          scanId: scan._id.toString(),
          projectId: scan.projectId.toString(),
          targetId: scan.targetId.toString(),
          ruleId: result.ruleId,
          title: result.title,
          description: result.description,
          impact: result.impact,
          severity: result.severity,
          confidence: result.confidence,
          category: result.category,
          endpoint: result.endpoint,
          method: result.method,
          parameter: result.parameter,
          remediation: result.remediation,
          cwe: result.cwe,
          owasp: result.owasp,
          apiOwasp: result.apiOwasp,
          references: result.references,
        });

        if (normalized) {
          await FindingModel.create(normalized);
          findingsCreated++;
        }
      }
    } catch (error) {
      logger.debug({ endpoint: ep.url, error: (error as Error).message }, 'Passive check error');
    }
  }

  await ScanModel.findByIdAndUpdate(scanId, {
    'progress.checksExecuted': checksExecuted,
    'progress.findingsTotal': findingsCreated,
  });

  logger.info({ scanId, checksExecuted, findingsCreated }, 'Passive analysis complete');
  return { checksExecuted, findingsCreated };
}
