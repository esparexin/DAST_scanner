import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

const SENSITIVE_PATHS = [
  '/.env',
  '/actuator/env',
  '/actuator/health',
  '/swagger-ui.html',
  '/api-docs',
  '/server-status',
  '/.git/HEAD',
];

export class ForcedBrowsingChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-AC-001',
          name: 'Exposed Administrative or Sensitive Debug Interface',
          description: 'Sensitive administrative or debug interfaces are directly accessible without authorization.',
          category: DetectionCategory.ACCESS_CONTROL,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
          cvssScore: 7.5,
          owasp: ['A01:2021', 'A05:2021'],
          apiOwasp: ['API5:2023'],
          cwe: ['CWE-285', 'CWE-538'],
          wstg: ['WSTG-CONF-04'],
          asvs: ['V4.1.3'],
          portswigger: ['https://portswigger.net/web-security/access-control'],
          remediation: 'Restrict access to administrative endpoints using IP whitelists and mandatory authentication.',
          references: [],
          enabled: true,
          tags: ['access-control', 'forced-browsing'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const results: CheckResult[] = [];
          const baseUrl = new URL(ctx.baseUrl);

          for (const path of SENSITIVE_PATHS) {
            const targetUrl = new URL(path, baseUrl).toString();
            try {
              const res = await ctx.httpClient.request({
                method: HttpMethod.GET,
                url: targetUrl,
              });

              // If HTTP 200 and not a generic custom 404 page
              if (res.statusCode === 200 && res.body.length > 0 && !res.body.includes('404')) {
                results.push({
                  ruleId: 'SEC-AC-001',
                  title: 'Exposed Sensitive Endpoint: ' + path,
                  description: `Found publicly accessible sensitive endpoint at ${targetUrl}`,
                  impact: 'Information disclosure of environment variables, server internals, or administrative functions.',
                  severity: Severity.HIGH,
                  confidence: Confidence.HIGH,
                  category: DetectionCategory.ACCESS_CONTROL,
                  endpoint: targetUrl,
                  method: 'GET',
                  remediation: 'Block public access to sensitive debugging paths in web server / reverse proxy configuration.',
                  cwe: ['CWE-285'],
                  owasp: ['A01:2021'],
                  apiOwasp: ['API5:2023'],
                  references: [],
                  evidence: {
                    request: { method: 'GET', url: targetUrl, headers: {} },
                    response: { statusCode: res.statusCode, headers: res.headers, body: res.body.slice(0, 300), responseTime: res.responseTime },
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
