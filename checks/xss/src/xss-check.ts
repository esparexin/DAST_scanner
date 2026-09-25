import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import {
  PayloadRegistry,
  PayloadSelector,
  MutationPipeline,
  PayloadTestExecutor,
  XSS_CATALOG,
} from '@securityscan/payload-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod, ScanProfile } from '@securityscan/contracts';

const defaultRegistry = new PayloadRegistry();
defaultRegistry.registerAll(XSS_CATALOG);

export class XssChecks {
  static getChecks(registry = defaultRegistry): SecurityCheck[] {
    const selector = new PayloadSelector(registry);
    const pipeline = new MutationPipeline();

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
          const executor = new PayloadTestExecutor(ctx.httpClient);

          for (const [key, value] of testUrl.searchParams.entries()) {
            const selectedPayloads = selector.select({
              name: key,
              location: 'query',
              type: 'string',
              category: DetectionCategory.XSS,
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

                  const contentType = executed.responseHeaders['content-type'] ?? '';
                  // Detect canary reflection in HTML context
                  if (contentType.includes('text/html') && executed.canaryObserved) {
                    results.push({
                      ruleId: 'SEC-XSS-001',
                      title: 'Reflected Cross-Site Scripting (XSS)',
                      description: `Parameter '${key}' reflects unescaped canary '${variant.canaryToken}' in an HTML context.`,
                      impact: 'Session hijacking, arbitrary script execution in authenticated victims browser context.',
                      severity: Severity.HIGH,
                      confidence: Confidence.CONFIRMED,
                      category: DetectionCategory.XSS,
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
