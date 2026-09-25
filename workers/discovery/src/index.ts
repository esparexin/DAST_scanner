import { Worker, type Job } from 'bullmq';
import { ScanModel, TargetModel, EndpointModel } from '@securityscan/database';
import { ScanStatus, HttpMethod, ScopeValidationResult } from '@securityscan/contracts';
import { ScopeGuard } from '@securityscan/scope';
import { SecureHttpClient, RateLimiter } from '@securityscan/http-client';
import { Crawler } from '@securityscan/crawler';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('worker-discovery');

export async function processDiscovery(job: Job) {
  const { scanId } = job.data as { scanId: string };
  logger.info({ scanId }, 'Starting discovery');

  const scan = await ScanModel.findById(scanId);
  if (!scan || scan.status === ScanStatus.CANCELLED) return;

  const target = await TargetModel.findById(scan.targetId);
  if (!target) throw new Error(`Target ${scan.targetId} not found`);

  // Build scope config
  const scopeConfig = {
    scanId: scan._id.toString(),
    targetId: target._id.toString(),
    projectId: scan.projectId.toString(),
    authorized: target.authorization === 'AUTHORIZED',
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
  const httpClient = new SecureHttpClient(validator, rateLimiter, {
    timeout: scopeConfig.timeoutPerRequest * 1000,
    maxResponseSize: scopeConfig.maxResponseSize,
  });

  // Update scan status
  await ScanModel.findByIdAndUpdate(scanId, {
    status: ScanStatus.DISCOVERING,
    startedAt: new Date(),
    'progress.phase': ScanStatus.DISCOVERING,
  });

  // Crawl
  await ScanModel.findByIdAndUpdate(scanId, {
    status: ScanStatus.CRAWLING,
    'progress.phase': ScanStatus.CRAWLING,
  });

  const crawler = new Crawler(httpClient, scopeConfig.maxCrawlDepth);
  const results = await crawler.crawl(target.baseUrl);

  // Store discovered endpoints
  const endpoints = [];
  for (const result of results) {
    const url = new URL(result.url);
    endpoints.push({
      scanId: scan._id,
      targetId: target._id,
      projectId: scan.projectId,
      method: HttpMethod.GET,
      url: result.url,
      path: url.pathname,
      parameters: [],
      headers: {},
      responseContentType: result.contentType,
      statusCode: result.statusCode,
      requiresAuth: false,
      discoverySource: 'crawler',
    });

    // Also add form endpoints
    for (const form of result.forms) {
      const formUrl = new URL(form.action);
      endpoints.push({
        scanId: scan._id,
        targetId: target._id,
        projectId: scan.projectId,
        method: form.method === 'POST' ? HttpMethod.POST : HttpMethod.GET,
        url: form.action,
        path: formUrl.pathname,
        parameters: form.inputs.map((i) => ({ name: i.name, location: 'body' as const, type: i.type })),
        headers: {},
        requiresAuth: false,
        discoverySource: 'form',
      });
    }
  }

  if (endpoints.length > 0) {
    await EndpointModel.insertMany(endpoints);
  }

  const stats = validator.getStats();
  await ScanModel.findByIdAndUpdate(scanId, {
    'progress.endpointsDiscovered': endpoints.length,
    'progress.completedRequests': stats.requestCount,
  });

  logger.info({ scanId, endpoints: endpoints.length, requests: stats.requestCount }, 'Discovery complete');
  return { endpoints: endpoints.length, requests: stats.requestCount };
}
