import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import {
  PayloadRegistry,
  PayloadSelector,
  MutationPipeline,
  PayloadTestExecutor,
  SQLI_CATALOG,
} from '@securityscan/payload-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod, ScanProfile } from '@securityscan/contracts';

const defaultRegistry = new PayloadRegistry();
defaultRegistry.registerAll(SQLI_CATALOG);

export class SqlInjectionChecks {
  static getChecks(registry = defaultRegistry): SecurityCheck[] {
    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();

    return [
      {
        rule: {
          id: 'SEC-SQLI-001',
          name: 'SQL Injection (Error-Based & Differential)',
          description: 'The application input appears vulnerable to SQL injection through database syntax disruption.',
          category: DetectionCategory.INJECTION,
          type: DetectionType.ACTIVE,
          severity: Severity.CRITICAL,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          cvssScore: 9.8,
          owasp: ['A03:2021'],
          apiOwasp: ['API8:2023'],
          cwe: ['CWE-89'],
          wstg: ['WSTG-INPV-05'],
          asvs: ['V5.3.4', 'V5.3.5'],
          portswigger: ['https://portswigger.net/web-security/sql-injection'],
          remediation: 'Use parameterized queries, prepared statements, or ORM parameter binding.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
          enabled: true,
          tags: ['sqli', 'injection'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          const results: CheckResult[] = [];
          const testUrl = new URL(ctx.endpoint.url);
          const executor = new PayloadTestExecutor(ctx.httpClient);

          for (const [key, value] of testUrl.searchParams.entries()) {
            // Use context-aware selector to pick calibrated SQLi payloads
            const selectedPayloads = selector.select({
              name: key,
              location: 'query',
              type: /^\d+$/.test(value) ? 'integer' : 'string',
              category: DetectionCategory.INJECTION,
              scanProfile: ScanProfile.WEB_STANDARD,
              maxProbesPerParam: 3,
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

                  // Match against error signatures defined in the payload metadata
                  const errorSignatures = payload.detection.errorSignatures ?? [];
                  for (const sig of errorSignatures) {
                    if (executed.responseBodySnippet.toLowerCase().includes(sig.toLowerCase())) {
                      results.push({
                        ruleId: 'SEC-SQLI-001',
                        title: 'SQL Injection Leaking Database Error',
                        description: `Parameter '${key}' leaked a database error signature '${sig}' with payload ${variant.description}.`,
                        impact: 'High-risk database compromise, unauthorized data extraction, and potential integrity tampering.',
                        severity: Severity.CRITICAL,
                        confidence: Confidence.CONFIRMED,
                        category: DetectionCategory.INJECTION,
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
                      return results; // Return early on confirmed critical finding
                    }
                  }
                } catch {
                  // Non-fatal loop continue
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
