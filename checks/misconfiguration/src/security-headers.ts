import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { PASSIVE_RULES } from '@securityscan/security-rules';
import { HttpMethod } from '@securityscan/contracts';

const hstsRule = PASSIVE_RULES.find((r) => r.id === 'SEC-HDR-001')!;
const xctoRule = PASSIVE_RULES.find((r) => r.id === 'SEC-HDR-002')!;
const xfoRule = PASSIVE_RULES.find((r) => r.id === 'SEC-HDR-003')!;
const cspRule = PASSIVE_RULES.find((r) => r.id === 'SEC-HDR-004')!;

function buildResult(
  rule: typeof hstsRule,
  ctx: CheckContext,
  response: { statusCode: number; headers: Record<string, string>; body: string; responseTime: number },
  requestUrl: string,
): CheckResult {
  return {
    ruleId: rule.id,
    title: rule.name,
    description: rule.description,
    impact: '',
    severity: rule.severity,
    confidence: rule.confidence,
    category: rule.category,
    endpoint: requestUrl,
    method: 'GET',
    remediation: rule.remediation,
    cwe: rule.cwe,
    owasp: rule.owasp,
    apiOwasp: rule.apiOwasp,
    references: rule.references,
    evidence: {
      request: { method: 'GET', url: requestUrl, headers: {} },
      response: {
        statusCode: response.statusCode,
        headers: response.headers,
        body: response.body.slice(0, 500),
        responseTime: response.responseTime,
      },
    },
  };
}

export class SecurityHeaderChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: hstsRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({
            method: HttpMethod.GET,
            url: ctx.endpoint.url,
          });
          const hsts = response.headers['strict-transport-security'];
          if (!hsts && ctx.endpoint.url.startsWith('https')) {
            return [buildResult(hstsRule, ctx, response, ctx.endpoint.url)];
          }
          return [];
        },
      },
      {
        rule: xctoRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({
            method: HttpMethod.GET,
            url: ctx.endpoint.url,
          });
          const xcto = response.headers['x-content-type-options'];
          if (!xcto || xcto.toLowerCase() !== 'nosniff') {
            return [buildResult(xctoRule, ctx, response, ctx.endpoint.url)];
          }
          return [];
        },
      },
      {
        rule: xfoRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({
            method: HttpMethod.GET,
            url: ctx.endpoint.url,
          });
          const xfo = response.headers['x-frame-options'];
          const csp = response.headers['content-security-policy'];
          if (!xfo && !(csp && csp.includes('frame-ancestors'))) {
            return [buildResult(xfoRule, ctx, response, ctx.endpoint.url)];
          }
          return [];
        },
      },
      {
        rule: cspRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({
            method: HttpMethod.GET,
            url: ctx.endpoint.url,
          });
          const csp = response.headers['content-security-policy'];
          if (!csp) {
            return [buildResult(cspRule, ctx, response, ctx.endpoint.url)];
          }
          return [];
        },
      },
    ];
  }
}
