import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence } from '@securityscan/contracts';

export class SsrfCandidateChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-SSRF-001',
          name: 'Server-Side Request Forgery (SSRF) Candidate Parameter',
          description: 'The endpoint accepts parameters that look like external destination URLs or fetch endpoints.',
          category: DetectionCategory.SSRF,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.MEDIUM,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
          cvssScore: 8.6,
          owasp: ['A10:2021'],
          apiOwasp: ['API7:2023'],
          cwe: ['CWE-918'],
          wstg: ['WSTG-INPV-19'],
          asvs: ['V12.6.1'],
          portswigger: ['https://portswigger.net/web-security/ssrf'],
          remediation: 'Validate destination URLs against a strict domain whitelist and disable HTTP redirection following on the server.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'],
          enabled: true,
          tags: ['ssrf'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const results: CheckResult[] = [];
          const testUrl = new URL(ctx.endpoint.url);

          for (const [key, value] of testUrl.searchParams.entries()) {
            const isUrlParam = /(url|uri|dest|destination|redirect|webhook|feed|fetch|source|remote)/i.test(key);
            const isUrlValue = /^https?:\/\//i.test(value);

            if (isUrlParam || isUrlValue) {
              results.push({
                ruleId: 'SEC-SSRF-001',
                title: 'Potential Server-Side Request Forgery Candidate Parameter',
                description: `Parameter '${key}' appears to accept destination URLs for server-side processing.`,
                impact: 'If unvalidated, attackers can coerce server to request cloud metadata or internal network assets.',
                severity: Severity.HIGH,
                confidence: Confidence.LOW,
                category: DetectionCategory.SSRF,
                endpoint: ctx.endpoint.url,
                method: 'GET',
                parameter: key,
                remediation: 'Enforce strict server-side allowlists for permitted URL domains.',
                cwe: ['CWE-918'],
                owasp: ['A10:2021'],
                apiOwasp: ['API7:2023'],
                references: [],
                evidence: {
                  request: { method: 'GET', url: ctx.endpoint.url, headers: {} },
                  response: { statusCode: 200, headers: {}, responseTime: 0 },
                },
              });
            }
          }

          return results;
        },
      },
    ];
  }
}
