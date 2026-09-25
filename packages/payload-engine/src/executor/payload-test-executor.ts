import type { SecureHttpClient } from '@securityscan/http-client';
import type { MaterializedTestVariant } from '../mutation/mutation-pipeline.js';
import { HttpMethod, type IHttpResponse } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('payload-executor');

export interface ExecutedTestResult {
  variant: MaterializedTestVariant;
  url: string;
  method: HttpMethod;
  statusCode: number;
  responseTimeMs: number;
  responseHeaders: Record<string, string>;
  responseBodySnippet: string;
  canaryObserved: boolean;
}

/**
 * Executes materialized test variants strictly through SecureHttpClient
 * ensuring Scope Gate, Private IP blocking, and Rate Limiting are enforced uniformly.
 */
export class PayloadTestExecutor {
  private readonly httpClient: SecureHttpClient;

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  async executeVariantOnUrlParam(
    targetUrl: string,
    paramName: string,
    variant: MaterializedTestVariant,
    method: HttpMethod = HttpMethod.GET,
  ): Promise<ExecutedTestResult> {
    const url = new URL(targetUrl);

    if (variant.isHppVariant) {
      // For HPP, append duplicate parameter key or array key
      const key = variant.hppKey ?? paramName;
      url.searchParams.append(key, variant.finalValue);
    } else {
      url.searchParams.set(paramName, variant.finalValue);
    }

    const fullUrl = url.toString();

    logger.debug(
      { payloadId: variant.payloadId, transform: variant.transformation, paramName },
      'Executing payload variant through SecureHttpClient',
    );

    const response: IHttpResponse = await this.httpClient.request({
      method,
      url: fullUrl,
    });

    const canaryObserved =
      variant.canaryToken !== undefined && response.body.includes(variant.canaryToken);

    return {
      variant,
      url: fullUrl,
      method,
      statusCode: response.statusCode,
      responseTimeMs: response.responseTime,
      responseHeaders: response.headers,
      responseBodySnippet: response.body.slice(0, 1000),
      canaryObserved,
    };
  }
}
