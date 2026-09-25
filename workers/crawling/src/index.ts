import { ScanModel, TargetModel, EndpointModel } from '@securityscan/database';
import { ScanStatus, HttpMethod } from '@securityscan/contracts';
import { ScopeGuard } from '@securityscan/scope';
import { SecureHttpClient, RateLimiter } from '@securityscan/http-client';
import { Crawler } from '@securityscan/crawler';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('worker-crawling');

export async function runCrawlWorker(scanId: string): Promise<number> {
  const scan = await ScanModel.findById(scanId);
  if (!scan || scan.status === ScanStatus.CANCELLED) return 0;

  const target = await TargetModel.findById(scan.targetId);
  if (!target || target.authorization !== 'AUTHORIZED') {
    throw new Error('Target not found or not authorized');
  }

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
  const crawler = new Crawler(httpClient, scopeConfig.maxCrawlDepth);

  logger.info({ scanId, targetUrl: target.baseUrl }, 'Starting crawling worker');
  const crawlResults = await crawler.crawl(target.baseUrl);

  const endpoints = crawlResults.map((r) => {
    const url = new URL(r.url);
    return {
      scanId: scan._id,
      targetId: target._id,
      projectId: scan.projectId,
      method: HttpMethod.GET,
      url: r.url,
      path: url.pathname,
      parameters: Array.from(url.searchParams.keys()).map((k) => ({ name: k, location: 'query' as const })),
      headers: {},
      responseContentType: r.contentType,
      statusCode: r.statusCode,
      requiresAuth: false,
      discoverySource: 'crawler' as const,
    };
  });

  if (endpoints.length > 0) {
    await EndpointModel.insertMany(endpoints);
  }

  await ScanModel.findByIdAndUpdate(scanId, {
    'progress.endpointsDiscovered': endpoints.length,
  });

  return endpoints.length;
}
