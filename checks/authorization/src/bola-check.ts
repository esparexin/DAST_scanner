import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence } from '@securityscan/contracts';

export class BolaChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-BOLA-001',
          name: 'Broken Object Level Authorization (BOLA/IDOR)',
          description: 'The endpoint does not enforce object-level authorization, allowing access to resources by manipulating identifier parameters.',
          category: DetectionCategory.AUTHORIZATION,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
          cvssScore: 8.1,
          owasp: ['A01:2021'],
          apiOwasp: ['API1:2023'],
          cwe: ['CWE-639'],
          wstg: ['WSTG-ATHZ-04'],
          asvs: ['V4.1.1', 'V4.1.2'],
          portswigger: ['https://portswigger.net/web-security/access-control/idor'],
          remediation: 'Implement server-side user-context object ownership verification prior to returning or modifying records.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'],
          enabled: true,
          tags: ['bola', 'idor', 'authorization'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const results: CheckResult[] = [];
          const url = new URL(ctx.endpoint.url);

          // Inspect if path contains a numeric resource ID, e.g. /users/42 or /orders/1001
          const numericIdMatch = /\/([0-9]{1,10})(?=\/|$)/.exec(url.pathname);
          if (numericIdMatch && numericIdMatch[1]) {
            const originalId = numericIdMatch[1];
            const peerId = originalId === '1' ? '2' : '1';
            const peerPath = url.pathname.replace(new RegExp(`/${originalId}(?=/|$)`), `/${peerId}`);
            const peerUrl = new URL(peerPath, url.origin).toString();

            try {
              const res = await ctx.httpClient.request({
                method: ctx.endpoint.method,
                url: peerUrl,
              });

              // If accessing the adjacent object returns 200 with valid content
              if (res.statusCode === 200 && res.body.length > 20) {
                results.push({
                  ruleId: 'SEC-BOLA-001',
                  title: 'Broken Object Level Authorization (BOLA/IDOR)',
                  description: `Endpoint allowed access to resource ID '${peerId}' by directly manipulating the path identifier from '${originalId}'.`,
                  impact: 'Horizontal privilege escalation allowing access to other users private records.',
                  severity: Severity.HIGH,
                  confidence: Confidence.CONFIRMED,
                  category: DetectionCategory.AUTHORIZATION,
                  endpoint: peerUrl,
                  method: ctx.endpoint.method,
                  parameter: originalId,
                  remediation: 'Validate that the currently authenticated user owns or has explicit permission for the requested object ID.',
                  cwe: ['CWE-639'],
                  owasp: ['A01:2021'],
                  apiOwasp: ['API1:2023'],
                  references: [],
                  evidence: {
                    request: { method: ctx.endpoint.method, url: peerUrl, headers: {} },
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
