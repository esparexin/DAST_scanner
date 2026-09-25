import type { NormalizedApiEndpoint } from '@securityscan/api-parser';
import { HttpMethod } from '@securityscan/contracts';

export interface ObservedEndpoint {
  path: string;
  method: HttpMethod;
  url: string;
}

export interface UndocumentedApiFinding {
  observedPath: string;
  observedMethod: HttpMethod;
  ruleId: string;
  title: string;
  description: string;
  owaspApi: string[];
  cwe: string[];
  severity: 'MEDIUM' | 'HIGH';
}

/**
 * Detects undocumented, shadow, or deprecated API endpoints (OWASP API9:2023 - Improper Inventory Management)
 */
export class UndocumentedEndpointDetector {
  detect(
    observed: ObservedEndpoint[],
    documentedEndpoints: NormalizedApiEndpoint[],
  ): UndocumentedApiFinding[] {
    const findings: UndocumentedApiFinding[] = [];

    for (const obs of observed) {
      // Check if this endpoint matches any documented route (supporting parameter paths like /users/{id})
      const isDocumented = documentedEndpoints.some((doc) => {
        if (doc.method !== obs.method) return false;
        return this.matchPath(doc.path, obs.path);
      });

      if (!isDocumented) {
        const isSensitiveRoute = /(admin|internal|debug|test|v0|v[0-9]|private|config|export)/i.test(obs.path);
        findings.push({
          observedPath: obs.path,
          observedMethod: obs.method,
          ruleId: 'SEC-API-009',
          title: isSensitiveRoute
            ? 'Undocumented Sensitive Shadow API Endpoint Discovered'
            : 'Undocumented API Endpoint Discovered',
          description: `The API endpoint '${obs.method} ${obs.path}' was discovered during crawling/testing but is missing from the declared API specification.`,
          owaspApi: ['API9:2023'],
          cwe: ['CWE-1059'],
          severity: isSensitiveRoute ? 'HIGH' : 'MEDIUM',
        });
      }
    }

    return findings;
  }

  private matchPath(pattern: string, actual: string): boolean {
    // Normalize trailing slashes
    const pNorm = pattern.replace(/\/+$/, '');
    const aNorm = actual.replace(/\/+$/, '');
    if (pNorm === aNorm) return true;

    // Convert /users/{id} to regex ^/users/[^/]+$
    const regexStr = '^' + pNorm.replace(/\{[^}]+\}/g, '[^/]+') + '$';
    try {
      return new RegExp(regexStr).test(aNorm);
    } catch {
      return false;
    }
  }
}
