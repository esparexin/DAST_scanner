import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class CleartextChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-CRYPTO-001',
          name: 'Cleartext HTTP Communication Channel',
          description: 'The target application serves traffic or receives authentication credentials over unencrypted HTTP.',
          category: DetectionCategory.CRYPTOGRAPHY,
          type: DetectionType.PASSIVE,
          severity: Severity.HIGH,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
          cvssScore: 5.9,
          owasp: ['A02:2021'],
          apiOwasp: ['API8:2023'],
          cwe: ['CWE-319'],
          wstg: ['WSTG-ATHN-01'],
          asvs: ['V9.1.1'],
          portswigger: [],
          remediation: 'Enforce HTTPS everywhere with HTTP Strict Transport Security (HSTS) and automatic 301 redirects.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'],
          enabled: true,
          tags: ['cryptography', 'cleartext'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          // Only check non-localhost HTTP endpoints
          const url = new URL(ctx.endpoint.url);
          if (url.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(url.hostname)) {
            return [{
              ruleId: 'SEC-CRYPTO-001',
              title: 'Unencrypted Cleartext HTTP Transmission',
              description: `Endpoint '${ctx.endpoint.url}' is served over unencrypted HTTP, leaving traffic vulnerable to interception.`,
              impact: 'Adversaries on the same network or upstream ISP can eavesdrop and tamper with requests in transit.',
              severity: Severity.HIGH,
              confidence: Confidence.CONFIRMED,
              category: DetectionCategory.CRYPTOGRAPHY,
              endpoint: ctx.endpoint.url,
              method: ctx.endpoint.method,
              remediation: 'Redirect all HTTP traffic to HTTPS and configure HSTS.',
              cwe: ['CWE-319'],
              owasp: ['A02:2021'],
              apiOwasp: ['API8:2023'],
              references: [],
              evidence: {
                request: { method: ctx.endpoint.method, url: ctx.endpoint.url, headers: {} },
                response: { statusCode: 200, headers: {}, responseTime: 0 },
              },
            }];
          }
          return [];
        },
      },
    ];
  }
}
