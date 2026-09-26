import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { JwtAnalyzer } from './jwt-analyzer.js';
import { DetectionCategory, DetectionType, Severity, Confidence } from '@securityscan/contracts';

export class JwtSecurityChecks {
  static getChecks(bearerToken?: string): SecurityCheck[] {
    if (!bearerToken) return [];
    const parsed = JwtAnalyzer.parse(bearerToken);
    if (!parsed) return [];

    return [
      // 1. None Algorithm Acceptance Check
      {
        rule: {
          id: 'SEC-JWT-001',
          name: 'JWT None-Algorithm Signature Bypass',
          description: 'The API accepts JWT tokens with alg: none, bypassing cryptographic signature verification.',
          category: DetectionCategory.AUTHENTICATION,
          type: DetectionType.ACTIVE,
          severity: Severity.CRITICAL,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          cvssScore: 9.1,
          owasp: ['A07:2021'],
          apiOwasp: ['API2:2023'],
          cwe: ['CWE-287', 'CWE-345'],
          wstg: ['WSTG-ATHN-01'],
          asvs: ['V3.5.2'],
          portswigger: ['https://portswigger.net/web-security/jwt'],
          remediation: 'Reject all tokens with alg: none. Enforce strict whitelist of permitted asymmetric or symmetric algorithms.',
          references: ['https://datatracker.ietf.org/doc/html/rfc7519'],
          enabled: true,
          tags: ['jwt', 'authentication', 'crypto'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const noneToken = JwtAnalyzer.createNoneAlgorithmMutant(parsed);
          const res = await ctx.httpClient.request({
            method: ctx.endpoint.method,
            url: ctx.endpoint.url,
            headers: {
              Authorization: `Bearer ${noneToken}`,
            },
          });

          // If endpoint still returns successful access (2xx) with alg: none, vulnerability confirmed
          if (res.statusCode >= 200 && res.statusCode < 300) {
            return [{
              ruleId: 'SEC-JWT-001',
              title: 'JWT None-Algorithm Signature Bypass',
              description: `Endpoint ${ctx.endpoint.url} accepted an unsigned token with alg: none.`,
              impact: 'Full authentication bypass; attackers can forge arbitrary identities and roles.',
              severity: Severity.CRITICAL,
              confidence: Confidence.CONFIRMED,
              category: DetectionCategory.AUTHENTICATION,
              endpoint: ctx.endpoint.url,
              method: ctx.endpoint.method,
              remediation: 'Configure JWT parser to reject algorithm none explicitly.',
              cwe: ['CWE-287', 'CWE-345'],
              owasp: ['A07:2021'],
              apiOwasp: ['API2:2023'],
              references: [],
              evidence: {
                request: { method: ctx.endpoint.method, url: ctx.endpoint.url, headers: { Authorization: `Bearer ${noneToken}` } },
                response: { statusCode: res.statusCode, headers: res.headers, responseTime: res.responseTime },
              },
            }];
          }
          return [];
        },
      },

      // 2. Invalid Signature Acceptance Check
      {
        rule: {
          id: 'SEC-JWT-002',
          name: 'JWT Missing Signature Verification',
          description: 'The endpoint does not verify the cryptographic signature of received JWT tokens.',
          category: DetectionCategory.AUTHENTICATION,
          type: DetectionType.ACTIVE,
          severity: Severity.CRITICAL,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          cvssScore: 9.1,
          owasp: ['A07:2021'],
          apiOwasp: ['API2:2023'],
          cwe: ['CWE-347'],
          wstg: ['WSTG-ATHN-01'],
          asvs: ['V3.5.1'],
          portswigger: ['https://portswigger.net/web-security/jwt'],
          remediation: 'Verify signature against trusted secret/public key before parsing claims.',
          references: [],
          enabled: true,
          tags: ['jwt', 'authentication'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const invalidToken = JwtAnalyzer.createInvalidSignatureMutant(parsed);
          const res = await ctx.httpClient.request({
            method: ctx.endpoint.method,
            url: ctx.endpoint.url,
            headers: { Authorization: `Bearer ${invalidToken}` },
          });

          if (res.statusCode >= 200 && res.statusCode < 300) {
            return [{
              ruleId: 'SEC-JWT-002',
              title: 'JWT Missing Signature Verification',
              description: `Endpoint ${ctx.endpoint.url} accepted a JWT with an invalid signature.`,
              impact: 'Any client can forge token claims and assume any identity or administrative role.',
              severity: Severity.CRITICAL,
              confidence: Confidence.CONFIRMED,
              category: DetectionCategory.AUTHENTICATION,
              endpoint: ctx.endpoint.url,
              method: ctx.endpoint.method,
              remediation: 'Ensure token signature verification is enforced prior to payload handling.',
              cwe: ['CWE-347'],
              owasp: ['A07:2021'],
              apiOwasp: ['API2:2023'],
              references: [],
              evidence: {
                request: { method: ctx.endpoint.method, url: ctx.endpoint.url, headers: { Authorization: `Bearer ${invalidToken}` } },
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
