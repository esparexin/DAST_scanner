import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class BflaChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-BFLA-001',
          name: 'Broken Function Level Authorization (BFLA)',
          description: 'Administrative or elevated functions are accessible without adequate role-based access control.',
          category: DetectionCategory.AUTHORIZATION,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          cvssScore: 9.1,
          owasp: ['A01:2021'],
          apiOwasp: ['API5:2023'],
          cwe: ['CWE-285'],
          wstg: ['WSTG-ATHZ-02'],
          asvs: ['V4.1.3'],
          portswigger: ['https://portswigger.net/web-security/access-control'],
          remediation: 'Implement server-side role validation on every administrative route and function.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'],
          enabled: true,
          tags: ['bfla', 'authorization', 'access-control'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const results: CheckResult[] = [];
          const url = new URL(ctx.endpoint.url);

          // Check if the endpoint path indicates an administrative or elevated function
          const isAdminPath = /(admin|manager|superuser|system|manage|privileged)/i.test(url.pathname);
          if (isAdminPath) {
            try {
              // Probe endpoint without authorization headers (anonymous baseline check)
              const res = await ctx.httpClient.request({
                method: ctx.endpoint.method,
                url: ctx.endpoint.url,
                headers: {},
              });

              // If the administrative function returns success without requiring auth/role
              if (res.statusCode >= 200 && res.statusCode < 300) {
                results.push({
                  ruleId: 'SEC-BFLA-001',
                  title: 'Broken Function Level Authorization (BFLA)',
                  description: `Administrative function '${ctx.endpoint.method} ${ctx.endpoint.url}' is accessible anonymously without role-based access control.`,
                  impact: 'Vertical privilege escalation allowing unauthorized callers to execute administrative actions.',
                  severity: Severity.HIGH,
                  confidence: Confidence.CONFIRMED,
                  category: DetectionCategory.AUTHORIZATION,
                  endpoint: ctx.endpoint.url,
                  method: ctx.endpoint.method,
                  remediation: 'Enforce strict role-based access control middleware verifying the caller possesses administrative authority.',
                  cwe: ['CWE-285'],
                  owasp: ['A01:2021'],
                  apiOwasp: ['API5:2023'],
                  references: [],
                  evidence: {
                    request: { method: ctx.endpoint.method, url: ctx.endpoint.url, headers: {} },
                    response: { statusCode: res.statusCode, headers: res.headers, body: res.body.slice(0, 500), responseTime: res.responseTime },
                  },
                });
              }
            } catch {
              // Safe continue
            }
          }

          return results;
        },
      },
    ];
  }
}
