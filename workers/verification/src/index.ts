import { ScanModel, TargetModel, FindingModel } from '@securityscan/database';
import { ScanStatus, HttpMethod, FindingStatus } from '@securityscan/contracts';
import { ScopeGuard } from '@securityscan/scope';
import { SecureHttpClient, RateLimiter } from '@securityscan/http-client';
import { VerificationEngine } from '@securityscan/verification-engine';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('worker-verification');

export async function runVerificationWorker(scanId: string): Promise<number> {
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
  const verificationEngine = new VerificationEngine(httpClient);

  // Auto-verify confirmed passive findings
  await FindingModel.updateMany(
    { scanId: scan._id, confidence: 'CONFIRMED', status: FindingStatus.CANDIDATE },
    { $set: { status: FindingStatus.VERIFIED, verifiedAt: new Date() } },
  );

  // Replay verification for active candidate findings
  const candidates = await FindingModel.find({
    scanId: scan._id,
    status: FindingStatus.CANDIDATE,
  });

  for (const c of candidates) {
    try {
      const result = await verificationEngine.verify(
        c.endpoint,
        c.method as HttpMethod,
        {},
        (status) => status >= 200 && status < 500,
      );
      if (result.status === FindingStatus.VERIFIED) {
        c.status = FindingStatus.VERIFIED;
        c.verifiedAt = new Date();
        await c.save();
      }
    } catch (err) {
      logger.debug({ endpoint: c.endpoint, error: (err as Error).message }, 'Verification replay error');
    }
  }

  const verifiedCount = await FindingModel.countDocuments({
    scanId: scan._id,
    status: FindingStatus.VERIFIED,
  });

  await ScanModel.findByIdAndUpdate(scanId, {
    'progress.findingsConfirmed': verifiedCount,
  });

  return verifiedCount;
}
