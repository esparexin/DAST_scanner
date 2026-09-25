import type { IRedactedHttpRequest, IRedactedHttpResponse } from '@securityscan/contracts';
import { redactSensitiveHeaders, redactSensitiveBody } from '@securityscan/shared';

export interface RawEvidence {
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  response: { statusCode: number; headers: Record<string, string>; body?: string; responseTime: number };
  endpoint: string;
  parameter?: string;
  authContext: string;
}

export interface CollectedEvidence {
  request: IRedactedHttpRequest;
  response: IRedactedHttpResponse;
  endpoint: string;
  parameter?: string;
  authContext: string;
  timestamp: Date;
  relevantHeaders: Record<string, string>;
  relevantResponseData: string;
}

export class EvidenceCollector {
  /**
   * Collect and redact evidence from a raw request/response pair.
   */
  collect(raw: RawEvidence): CollectedEvidence {
    return {
      request: {
        method: raw.request.method,
        url: raw.request.url,
        headers: redactSensitiveHeaders(raw.request.headers),
        body: raw.request.body ? redactSensitiveBody(raw.request.body) : undefined,
      },
      response: {
        statusCode: raw.response.statusCode,
        headers: redactSensitiveHeaders(raw.response.headers),
        body: raw.response.body
          ? redactSensitiveBody(raw.response.body).slice(0, 50000)
          : undefined,
        responseTime: raw.response.responseTime,
      },
      endpoint: raw.endpoint,
      parameter: raw.parameter,
      authContext: raw.authContext,
      timestamp: new Date(),
      relevantHeaders: this.extractRelevantHeaders(raw.response.headers),
      relevantResponseData: this.extractRelevantData(raw.response.body ?? ''),
    };
  }

  private extractRelevantHeaders(headers: Record<string, string>): Record<string, string> {
    const securityHeaders = [
      'content-security-policy',
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'x-xss-protection',
      'access-control-allow-origin',
      'access-control-allow-credentials',
      'server',
      'x-powered-by',
    ];
    const relevant: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (securityHeaders.includes(key.toLowerCase())) {
        relevant[key] = value;
      }
    }
    return relevant;
  }

  private extractRelevantData(body: string): string {
    return body.slice(0, 2000);
  }
}
