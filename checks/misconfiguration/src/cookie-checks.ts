import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { PASSIVE_RULES } from '@securityscan/security-rules';
import { HttpMethod } from '@securityscan/contracts';

const httpOnlyRule = PASSIVE_RULES.find((r) => r.id === 'SEC-COOKIE-001')!;
const secureRule = PASSIVE_RULES.find((r) => r.id === 'SEC-COOKIE-002')!;
const sameSiteRule = PASSIVE_RULES.find((r) => r.id === 'SEC-COOKIE-003')!;

export class CookieChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: httpOnlyRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({ method: HttpMethod.GET, url: ctx.endpoint.url });
          const results: CheckResult[] = [];
          const setCookies = response.headers['set-cookie'];
          if (setCookies) {
            for (const cookie of setCookies.split(',')) {
              if (!cookie.toLowerCase().includes('httponly')) {
                results.push({
                  ruleId: httpOnlyRule.id, title: httpOnlyRule.name, description: httpOnlyRule.description,
                  impact: '', severity: httpOnlyRule.severity, confidence: httpOnlyRule.confidence,
                  category: httpOnlyRule.category, endpoint: ctx.endpoint.url, method: 'GET',
                  parameter: cookie.split('=')[0]?.trim(), remediation: httpOnlyRule.remediation,
                  cwe: httpOnlyRule.cwe, owasp: httpOnlyRule.owasp, apiOwasp: httpOnlyRule.apiOwasp,
                  references: httpOnlyRule.references,
                  evidence: {
                    request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
                    response: { statusCode: response.statusCode, headers: response.headers, responseTime: response.responseTime },
                  },
                });
              }
            }
          }
          return results;
        },
      },
      {
        rule: secureRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({ method: HttpMethod.GET, url: ctx.endpoint.url });
          const results: CheckResult[] = [];
          const setCookies = response.headers['set-cookie'];
          if (setCookies && ctx.endpoint.url.startsWith('https')) {
            for (const cookie of setCookies.split(',')) {
              if (!cookie.toLowerCase().includes('secure')) {
                results.push({
                  ruleId: secureRule.id, title: secureRule.name, description: secureRule.description,
                  impact: '', severity: secureRule.severity, confidence: secureRule.confidence,
                  category: secureRule.category, endpoint: ctx.endpoint.url, method: 'GET',
                  parameter: cookie.split('=')[0]?.trim(), remediation: secureRule.remediation,
                  cwe: secureRule.cwe, owasp: secureRule.owasp, apiOwasp: secureRule.apiOwasp,
                  references: secureRule.references,
                  evidence: {
                    request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
                    response: { statusCode: response.statusCode, headers: response.headers, responseTime: response.responseTime },
                  },
                });
              }
            }
          }
          return results;
        },
      },
      {
        rule: sameSiteRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({ method: HttpMethod.GET, url: ctx.endpoint.url });
          const results: CheckResult[] = [];
          const setCookies = response.headers['set-cookie'];
          if (setCookies) {
            for (const cookie of setCookies.split(',')) {
              if (!cookie.toLowerCase().includes('samesite')) {
                results.push({
                  ruleId: sameSiteRule.id, title: sameSiteRule.name, description: sameSiteRule.description,
                  impact: '', severity: sameSiteRule.severity, confidence: sameSiteRule.confidence,
                  category: sameSiteRule.category, endpoint: ctx.endpoint.url, method: 'GET',
                  parameter: cookie.split('=')[0]?.trim(), remediation: sameSiteRule.remediation,
                  cwe: sameSiteRule.cwe, owasp: sameSiteRule.owasp, apiOwasp: sameSiteRule.apiOwasp,
                  references: sameSiteRule.references,
                  evidence: {
                    request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
                    response: { statusCode: response.statusCode, headers: response.headers, responseTime: response.responseTime },
                  },
                });
              }
            }
          }
          return results;
        },
      },
    ];
  }
}
