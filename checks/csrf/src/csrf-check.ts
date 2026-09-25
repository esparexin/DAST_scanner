import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class CsrfChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-CSRF-001',
          name: 'Missing Anti-CSRF Token on State-Changing Endpoint',
          description: 'The state-changing request endpoint does not require anti-CSRF token verification.',
          category: DetectionCategory.CSRF,
          type: DetectionType.ACTIVE,
          severity: Severity.MEDIUM,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
          cvssScore: 6.5,
          owasp: ['A01:2021'],
          apiOwasp: [],
          cwe: ['CWE-352'],
          wstg: ['WSTG-SESS-05'],
          asvs: ['V4.2.1', 'V4.2.2'],
          portswigger: ['https://portswigger.net/web-security/csrf'],
          remediation: 'Implement synchronized Anti-CSRF tokens or use SameSite=Strict on session cookies.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
          enabled: true,
          tags: ['csrf'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          // Only analyze state-changing methods
          if (ctx.endpoint.method === HttpMethod.GET || ctx.endpoint.method === HttpMethod.HEAD) {
            return [];
          }

          // Submit request omitting common CSRF token headers
          const res = await ctx.httpClient.request({
            method: ctx.endpoint.method,
            url: ctx.endpoint.url,
            headers: {
              Origin: 'https://untrusted-origin.corp',
            },
          });

          // If the server accepts state change without rejecting (403/401/400 CSRF validation error)
          if (res.statusCode >= 200 && res.statusCode < 300) {
            return [{
              ruleId: 'SEC-CSRF-001',
              title: 'Missing Anti-CSRF Protection on State-Changing Endpoint',
              description: `Endpoint ${ctx.endpoint.method} ${ctx.endpoint.url} succeeded with an external cross-origin header and no CSRF token.`,
              impact: 'Attacker can forge actions on behalf of authenticated users via malicious web pages.',
              severity: Severity.MEDIUM,
              confidence: Confidence.CONFIRMED,
              category: DetectionCategory.CSRF,
              endpoint: ctx.endpoint.url,
              method: ctx.endpoint.method,
              remediation: 'Require CSRF token validation or enforce custom header requirements (e.g. X-Requested-With) on state mutations.',
              cwe: ['CWE-352'],
              owasp: ['A01:2021'],
              apiOwasp: [],
              references: [],
              evidence: {
                request: { method: ctx.endpoint.method, url: ctx.endpoint.url, headers: { Origin: 'https://untrusted-origin.corp' } },
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
