import type { SecureHttpClient } from './secure-http-client.js';
import { HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('rate-limit-engine');

export interface RateLimitAnalysisResult {
  endpointUrl: string;
  status: 'ENFORCED' | 'PARTIAL' | 'ABSENT';
  burstAttemptsSent: number;
  rateLimitHeadersDetected: Record<string, string>;
  throttlingStatusCode?: number;
  retryAfterHeader?: string;
  latencyDeltaMs: number;
  findingDescription?: string;
}

export interface BoundedRateLimitOptions {
  maxBurstRequests?: number; // Hard ceiling to avoid DoS (default 6, max 15)
  concurrency?: number;
}

/**
 * Controlled, bounded rate-limit and resource-consumption assessment engine.
 * Probes for 429 Too Many Requests, Retry-After, and rate limit headers safely.
 */
export class RateLimitEngine {
  private readonly httpClient: SecureHttpClient;

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  async assessEndpoint(
    url: string,
    method: HttpMethod = HttpMethod.GET,
    options?: BoundedRateLimitOptions,
  ): Promise<RateLimitAnalysisResult> {
    // Strictly bounded: never send more than 15 requests to preserve target stability
    const burstCount = Math.min(options?.maxBurstRequests ?? 6, 15);
    logger.info({ url, burstCount }, 'Initiating bounded rate-limit assessment');

    const detectedHeaders: Record<string, string> = {};
    let throttlingCode: number | undefined;
    let retryAfter: string | undefined;
    const latencies: number[] = [];

    for (let i = 0; i < burstCount; i++) {
      try {
        const res = await this.httpClient.request({
          method,
          url,
        });

        latencies.push(res.responseTime);

        // Inspect standard and vendor rate limit headers
        for (const [key, val] of Object.entries(res.headers)) {
          const lk = key.toLowerCase();
          if (
            lk.includes('ratelimit') ||
            lk === 'retry-after' ||
            lk.startsWith('x-rate-limit') ||
            lk.startsWith('x-ratelimit')
          ) {
            detectedHeaders[key] = val;
          }
          if (lk === 'retry-after') {
            retryAfter = val;
          }
        }

        if (res.statusCode === 429 || res.statusCode === 503) {
          throttlingCode = res.statusCode;
          logger.info({ url, attempt: i + 1, statusCode: res.statusCode }, 'Rate limit triggered by target');
          break; // Stop immediately once target throttles
        }
      } catch (err) {
        logger.debug({ url, attempt: i, error: (err as Error).message }, 'Rate-limit probe request failed');
        break;
      }
    }

    const baselineLatency = latencies[0] ?? 0;
    const lastLatency = latencies[latencies.length - 1] ?? 0;
    const latencyDelta = Math.max(0, lastLatency - baselineLatency);

    let status: RateLimitAnalysisResult['status'];
    let description: string | undefined;

    if (throttlingCode === 429 || retryAfter !== undefined) {
      status = 'ENFORCED';
      description = `Target actively enforces rate limiting (HTTP ${throttlingCode ?? 200}${retryAfter ? `, Retry-After: ${retryAfter}` : ''}).`;
    } else if (Object.keys(detectedHeaders).length > 0) {
      status = 'PARTIAL';
      description = 'Target provides rate limit headers but did not throttle within the safe probe volume.';
    } else {
      status = 'ABSENT';
      description = 'No rate limiting headers or throttling behavior observed under bounded probe conditions (OWASP API4:2023).';
    }

    return {
      endpointUrl: url,
      status,
      burstAttemptsSent: latencies.length,
      rateLimitHeadersDetected: detectedHeaders,
      throttlingStatusCode: throttlingCode,
      retryAfterHeader: retryAfter,
      latencyDeltaMs: latencyDelta,
      findingDescription: description,
    };
  }
}
