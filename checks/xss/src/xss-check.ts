import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class XssChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-XSS-001',
          name: 'Reflected Cross-Site Scripting (XSS)',
          description: 'Parameter values are reflected back in HTML responses without context-aware HTML entity encoding.',
          category: DetectionCategory.XSS,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
          cvssScore: 6.1,
          owasp: ['A03:2021'],
          apiOwasp: [],
          cwe: ['CWE-79'],
          wstg: ['WSTG-INPV-01'],
          asvs: ['V5.3.1', 'V5.3.3'],
          portswigger: ['https://portswigger.net/web-security/cross-site-scripting/reflected'],
          remediation: 'Implement contextual output encoding (e.g. HTML entity encoding) and deploy Content-Security-Policy.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
          enabled: true,
          tags: ['xss', 'injection'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const results: CheckResult[] = [];
          const testUrl = new URL(ctx.endpoint.url);

          for (const [key] of testUrl.searchParams.entries()) {
            // Safe, unique random alphanumeric canary tag
            const canary = `xsscanary${Math.random().toString(36).slice(2, 8)}`;
            const probePayload = `<${canary}>`;
            const probeUrl = new URL(ctx.endpoint.url);
            probeUrl.searchParams.set(key, probePayload);

            try {
              const res = await ctx.httpClient.request({
                method: HttpMethod.GET,
                url: probeUrl.toString(),
              });

              const contentType = res.headers['content-type'] ?? '';
              // Only report if returned as HTML and payload is unescaped
              if (contentType.includes('text/html') && res.body.includes(probePayload)) {
                results.push({
                  ruleId: 'SEC-XSS-001',
                  title: 'Reflected Cross-Site Scripting (XSS)',
                  description: `Parameter '${key}' reflects unescaped markup in an HTML context.`,
                  impact: 'Session hijacking, arbitrary script execution in authenticated victims browser context.',
                  severity: Severity.HIGH,
                  confidence: Confidence.CONFIRMED,
                  category: DetectionCategory.XSS,
                  endpoint: ctx.endpoint.url,
                  method: 'GET',
                  parameter: key,
                  remediation: 'Ensure user input reflected into HTML context is strictly HTML-entity encoded.',
                  cwe: ['CWE-79'],
                  owasp: ['A03:2021'],
                  apiOwasp: [],
                  references: [],
                  evidence: {
                    request: { method: 'GET', url: probeUrl.toString(), headers: {} },
                    response: { statusCode: res.statusCode, headers: res.headers, body: res.body.slice(0, 1000), responseTime: res.responseTime },
                  },
                });
              }
            } catch {
              // Non-fatal loop continue
            }
          }

          return results;
        },
      },
    ];
  }
}
