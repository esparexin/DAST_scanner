import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { PASSIVE_RULES } from '@securityscan/security-rules';
import { HttpMethod } from '@securityscan/contracts';

const corsRule = PASSIVE_RULES.find((r) => r.id === 'SEC-CORS-001')!;

export class CorsChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: corsRule,
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const response = await ctx.httpClient.request({ method: HttpMethod.GET, url: ctx.endpoint.url });
          const acao = response.headers['access-control-allow-origin'];
          if (acao === '*') {
            const acac = response.headers['access-control-allow-credentials'];
            return [
              {
                ruleId: corsRule.id, title: corsRule.name, description: corsRule.description,
                impact: acac === 'true' ? 'Wildcard origin with credentials enabled' : '',
                severity: corsRule.severity, confidence: corsRule.confidence,
                category: corsRule.category, endpoint: ctx.endpoint.url, method: 'GET',
                remediation: corsRule.remediation, cwe: corsRule.cwe, owasp: corsRule.owasp,
                apiOwasp: corsRule.apiOwasp, references: corsRule.references,
                evidence: {
                  request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
                  response: { statusCode: response.statusCode, headers: response.headers, responseTime: response.responseTime },
                },
              },
            ];
          }
          return [];
        },
      },
    ];
  }
}
