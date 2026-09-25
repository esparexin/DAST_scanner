import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

// Common deterministic database error signatures
const SQL_ERROR_PATTERNS = [
  // PostgreSQL
  /syntax error at or near/i,
  /invalid input syntax for/i,
  /pg_query\(\):/i,
  // MySQL / MariaDB
  /you have an error in your sql syntax/i,
  /check the manual that corresponds to your (mysql|mariadb)/i,
  /warning: mysql_/i,
  // SQLite
  /unrecognized token:/i,
  /sqlite3::sqlexception/i,
  // SQL Server
  /unclosed quotation mark after the character string/i,
  /microsoft ole db provider for sql server/i,
  // Oracle
  /ora-01756: quoted string not properly terminated/i,
  /ora-00933: sql command not properly ended/i,
];

export class SqlInjectionChecks {
  static getChecks(): SecurityCheck[] {
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

          // Check each query parameter safely using benign canary probe
          for (const [key, value] of testUrl.searchParams.entries()) {
            const probeUrl = new URL(ctx.endpoint.url);
            // Disruption probe
            probeUrl.searchParams.set(key, `${value}'"`);

            try {
              const res = await ctx.httpClient.request({
                method: HttpMethod.GET,
                url: probeUrl.toString(),
              });

              // Check if any well-known database error is leaked
              for (const pattern of SQL_ERROR_PATTERNS) {
                if (pattern.test(res.body)) {
                  results.push({
                    ruleId: 'SEC-SQLI-001',
                    title: 'SQL Injection Leaking Database Error',
                    description: `Parameter '${key}' leaked a database error signature when tested with quote characters.`,
                    impact: 'High-risk database compromise, unauthorized data extraction, and potential integrity tampering.',
                    severity: Severity.CRITICAL,
                    confidence: Confidence.CONFIRMED,
                    category: DetectionCategory.INJECTION,
                    endpoint: ctx.endpoint.url,
                    method: 'GET',
                    parameter: key,
                    remediation: 'Implement parameterized statements and disable verbose database error messages in production.',
                    cwe: ['CWE-89'],
                    owasp: ['A03:2021'],
                    apiOwasp: ['API8:2023'],
                    references: [],
                    evidence: {
                      request: { method: 'GET', url: probeUrl.toString(), headers: {} },
                      response: { statusCode: res.statusCode, headers: res.headers, body: res.body.slice(0, 1000), responseTime: res.responseTime },
                    },
                  });
                  break; // Found one pattern for this param
                }
              }
            } catch {
              // Scope or connectivity check failure is non-fatal for loop
            }
          }

          return results;
        },
      },
    ];
  }
}
