import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class OAuthSecurityChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-OAUTH-001',
          name: 'OAuth 2.0 Missing State Parameter',
          description: 'OAuth authorization requests do not enforce an unguessable state parameter, leaving users vulnerable to OAuth login CSRF.',
          category: DetectionCategory.AUTHENTICATION,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.HIGH,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
          cvssScore: 8.1,
          owasp: ['A01:2021', 'A07:2021'],
          apiOwasp: ['API2:2023'],
          cwe: ['CWE-352'],
          wstg: ['WSTG-SESS-05'],
          asvs: ['V3.1.1'],
          portswigger: ['https://portswigger.net/web-security/oauth'],
          remediation: 'Enforce a cryptographically random, session-bound state parameter in OAuth authorization requests.',
          references: ['https://datatracker.ietf.org/doc/html/rfc6749#section-10.12'],
          enabled: true,
          tags: ['oauth', 'csrf'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          // Only check endpoints that look like oauth authorization endpoints
          if (!/\/(oauth|auth|authorize)/i.test(ctx.endpoint.url)) return [];

          const testUrl = new URL(ctx.endpoint.url);
          testUrl.searchParams.delete('state');

          const res = await ctx.httpClient.request({
            method: HttpMethod.GET,
            url: testUrl.toString(),
          });

          // If the endpoint redirects or responds with code without complaining about missing state
          if ((res.statusCode === 200 || res.statusCode === 302) && !res.body.toLowerCase().includes('state')) {
            return [{
              ruleId: 'SEC-OAUTH-001',
              title: 'OAuth 2.0 Missing State Parameter',
              description: `OAuth endpoint ${ctx.endpoint.url} accepted an authorization request without a state parameter.`,
              impact: 'Enables OAuth Login CSRF where an attacker can bind an unsuspecting victims account to the attackers identity.',
              severity: Severity.HIGH,
              confidence: Confidence.MEDIUM,
              category: DetectionCategory.AUTHENTICATION,
              endpoint: ctx.endpoint.url,
              method: 'GET',
              remediation: 'Require valid state parameter on all authorization grant flows.',
              cwe: ['CWE-352'],
              owasp: ['A01:2021'],
              apiOwasp: ['API2:2023'],
              references: [],
              evidence: {
                request: { method: 'GET', url: testUrl.toString(), headers: {} },
                response: { statusCode: res.statusCode, headers: res.headers, responseTime: res.responseTime },
              },
            }];
          }
          return [];
        },
      },
    ];
  }
}
