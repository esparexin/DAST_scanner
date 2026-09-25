import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import {
  PayloadRegistry,
  PayloadSelector,
  MutationPipeline,
  PayloadTestExecutor,
  TRAVERSAL_CATALOG,
} from '@securityscan/payload-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod, ScanProfile } from '@securityscan/contracts';

const defaultRegistry = new PayloadRegistry();
defaultRegistry.registerAll(TRAVERSAL_CATALOG);

export class PathTraversalChecks {
  static getChecks(registry = defaultRegistry): SecurityCheck[] {
    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();

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
          const executor = new PayloadTestExecutor(ctx.httpClient);

          for (const [key, value] of testUrl.searchParams.entries()) {
            if (!/(file|path|doc|template|page|include|image|load)/i.test(key)) continue;

            const selectedPayloads = selector.select({
              name: key,
              location: 'query',
              type: 'file',
              category: DetectionCategory.PATH_TRAVERSAL,
              scanProfile: ScanProfile.WEB_STANDARD,
              maxProbesPerParam: 2,
            });

            for (const payload of selectedPayloads) {
              const variants = pipeline.materialize(payload, key, value);

              for (const variant of variants) {
                try {
                  const executed = await executor.executeVariantOnUrlParam(
                    ctx.endpoint.url,
                    key,
                    variant,
                    HttpMethod.GET,
                  );

                  const errorSignatures = payload.detection.errorSignatures ?? [];
                  for (const sig of errorSignatures) {
                    if (executed.responseBodySnippet.includes(sig)) {
                      results.push({
                        ruleId: 'SEC-PT-001',
                        title: 'Arbitrary File Read via Path Traversal',
                        description: `Parameter '${key}' allowed directory traversal to access system files using ${variant.description}.`,
                        impact: 'Full disclosure of sensitive configuration files, source code, and credentials.',
                        severity: Severity.HIGH,
                        confidence: Confidence.CONFIRMED,
                        category: DetectionCategory.PATH_TRAVERSAL,
                        endpoint: ctx.endpoint.url,
                        method: 'GET',
                        parameter: key,
                        remediation: payload.remediation.guidance,
                        cwe: payload.references.cwe,
                        owasp: payload.references.owaspTop10,
                        apiOwasp: payload.references.owaspApiSecurity,
                        references: [],
                        evidence: {
                          request: { method: 'GET', url: executed.url, headers: {} },
                          response: {
                            statusCode: executed.statusCode,
                            headers: executed.responseHeaders,
                            body: executed.responseBodySnippet,
                            responseTime: executed.responseTimeMs,
                          },
                        },
                      });
                      return results; // Return early on confirmed finding
                    }
                  }
                } catch {
                  // Safe continue
                }
              }
            }
          }

          return results;
        },
      },
    ];
  }
}
