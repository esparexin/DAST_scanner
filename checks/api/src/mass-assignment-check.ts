import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class MassAssignmentChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-API-003-MASS',
          name: 'API Mass Assignment / Property Injection',
          description: 'The endpoint accepts unexpected administrative properties in JSON payload and binds them.',
          category: DetectionCategory.API_SECURITY,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
          cvssScore: 8.1,
          owasp: ['A04:2021'],
          apiOwasp: ['API3:2023'],
          cwe: ['CWE-915'],
          wstg: ['WSTG-APIT-01'],
          asvs: ['V5.1.4'],
          portswigger: ['https://portswigger.net/web-security/api-testing'],
          remediation: 'Use strict DTOs / allowlists for incoming payload binding. Reject undeclared properties.',
          references: [],
          enabled: true,
          tags: ['mass-assignment', 'api'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          // Only test mutation methods (POST, PUT, PATCH)
          if (![HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH].includes(ctx.endpoint.method)) {
            return [];
          }

          // Inject elevated attributes
          const probeBody = JSON.stringify({
            role: 'admin',
            isAdmin: true,
            is_admin: true,
          });

          try {
            const res = await ctx.httpClient.request({
              method: ctx.endpoint.method,
              url: ctx.endpoint.url,
              headers: { 'Content-Type': 'application/json' },
              body: probeBody,
            });

            // If response echoes back the injected role: admin
            if (res.statusCode >= 200 && res.statusCode < 300 && (res.body.includes('"admin"') || res.body.includes('"isAdmin":true'))) {
              return [{
                ruleId: 'SEC-API-003-MASS',
                title: 'API Mass Assignment: Elevated Privilege Property Bound',
                description: `Endpoint ${ctx.endpoint.method} ${ctx.endpoint.url} accepted and bound injected 'role: admin' / 'isAdmin: true' attributes.`,
                impact: 'Privilege escalation enabling regular users to assign themselves administrative access.',
                severity: Severity.HIGH,
                confidence: Confidence.CONFIRMED,
                category: DetectionCategory.API_SECURITY,
                endpoint: ctx.endpoint.url,
                method: ctx.endpoint.method,
                remediation: 'Explicitly whitelist permitted object properties in request deserialization layer.',
                cwe: ['CWE-915'],
                owasp: ['A04:2021'],
                apiOwasp: ['API3:2023'],
                references: [],
                evidence: {
                  request: { method: ctx.endpoint.method, url: ctx.endpoint.url, headers: { 'Content-Type': 'application/json' }, body: probeBody },
                  response: { statusCode: res.statusCode, headers: res.headers, body: res.body.slice(0, 500), responseTime: res.responseTime },
                },
              }];
            }
          } catch {
            // Safe ignore
          }
          return [];
        },
      },
    ];
  }
}
