import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class PathTraversalChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-PT-001',
          name: 'Path Traversal / Local File Access',
          description: 'The application allows relative path sequences (../) in file parameters, exposing local filesystem contents.',
          category: DetectionCategory.PATH_TRAVERSAL,
          type: DetectionType.ACTIVE,
          severity: Severity.HIGH,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
          cvssScore: 7.5,
          owasp: ['A01:2021'],
          apiOwasp: [],
          cwe: ['CWE-22'],
          wstg: ['WSTG-ATHZ-01'],
          asvs: ['V12.3.1'],
          portswigger: ['https://portswigger.net/web-security/file-path-traversal'],
          remediation: 'Validate input against an allowlist of permitted filenames. Strip directory paths and use index identifiers.',
          references: [],
          enabled: true,
          tags: ['path-traversal'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const results: CheckResult[] = [];
          const testUrl = new URL(ctx.endpoint.url);

          for (const [key] of testUrl.searchParams.entries()) {
            // Common file parameter candidates
            if (!/(file|path|doc|template|page|include|image|load)/i.test(key)) continue;

            const traversalProbe = '../../../../etc/passwd';
            const probeUrl = new URL(ctx.endpoint.url);
            probeUrl.searchParams.set(key, traversalProbe);

            try {
              const res = await ctx.httpClient.request({
                method: HttpMethod.GET,
                url: probeUrl.toString(),
              });

              // Check for root user line signature in standard Unix passwd file format
              if (/root:x?:0:0:[^:]*:\/root:/i.test(res.body)) {
                results.push({
                  ruleId: 'SEC-PT-001',
                  title: 'Arbitrary File Read via Path Traversal',
                  description: `Parameter '${key}' allowed directory traversal to access system configuration files.`,
                  impact: 'Full disclosure of sensitive configuration files, source code, and credentials.',
                  severity: Severity.HIGH,
                  confidence: Confidence.CONFIRMED,
                  category: DetectionCategory.PATH_TRAVERSAL,
                  endpoint: ctx.endpoint.url,
                  method: 'GET',
                  parameter: key,
                  remediation: 'Resolve absolute canonical paths and verify the resulting path stays within intended root.',
                  cwe: ['CWE-22'],
                  owasp: ['A01:2021'],
                  apiOwasp: [],
                  references: [],
                  evidence: {
                    request: { method: 'GET', url: probeUrl.toString(), headers: {} },
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
