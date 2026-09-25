import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { PASSIVE_RULES } from '@securityscan/security-rules';
import { HttpMethod } from '@securityscan/contracts';

const serverRule = PASSIVE_RULES.find((r) => r.id === 'SEC-HDR-005')!;
const poweredByRule = PASSIVE_RULES.find((r) => r.id === 'SEC-HDR-006')!;

export class InfoDisclosureChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: serverRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({ method: HttpMethod.GET, url: ctx.endpoint.url });
          const server = response.headers['server'];
          if (server && /\/[\d.]/.test(server)) {
            return [{
              ruleId: serverRule.id, title: serverRule.name, description: `Server header discloses: ${server}`,
              impact: '', severity: serverRule.severity, confidence: serverRule.confidence,
              category: serverRule.category, endpoint: ctx.endpoint.url, method: 'GET',
              remediation: serverRule.remediation, cwe: serverRule.cwe, owasp: serverRule.owasp,
              apiOwasp: serverRule.apiOwasp, references: serverRule.references,
              evidence: {
                request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
                response: { statusCode: response.statusCode, headers: response.headers, responseTime: response.responseTime },
              },
            }];
          }
          return [];
        },
      },
      {
        rule: poweredByRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({ method: HttpMethod.GET, url: ctx.endpoint.url });
          const xpb = response.headers['x-powered-by'];
          if (xpb) {
            return [{
              ruleId: poweredByRule.id, title: poweredByRule.name, description: `X-Powered-By discloses: ${xpb}`,
              impact: '', severity: poweredByRule.severity, confidence: poweredByRule.confidence,
              category: poweredByRule.category, endpoint: ctx.endpoint.url, method: 'GET',
              remediation: poweredByRule.remediation, cwe: poweredByRule.cwe, owasp: poweredByRule.owasp,
              apiOwasp: poweredByRule.apiOwasp, references: poweredByRule.references,
              evidence: {
                request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
                response: { statusCode: response.statusCode, headers: response.headers, responseTime: response.responseTime },
              },
            }];
          }
          return [];
        },
      },
    ];
  }
}
