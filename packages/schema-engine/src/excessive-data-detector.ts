export interface ExcessiveDataFinding {
  endpoint: string;
  method: string;
  exposedProperty: string;
  sensitivityReason: string;
  ruleId: string;
  title: string;
  description: string;
  owaspApi: string[];
  cwe: string[];
  severity: 'HIGH' | 'CRITICAL';
}

const SENSITIVE_KEY_PATTERNS = [
  { pattern: /^(password|passwd|pwd|pass_?hash|password_?hash|secret|private_?key)$/i, reason: 'Credential field exposed in API response', severity: 'CRITICAL' as const },
  { pattern: /^(ssn|social_security|national_id|tax_id)$/i, reason: 'Government/National identifier exposed in API response', severity: 'CRITICAL' as const },
  { pattern: /^(credit_?card|card_?number|cvv|cvc)$/i, reason: 'Financial cardholder information exposed in response', severity: 'CRITICAL' as const },
  { pattern: /^(auth_?token|api_?key|access_?token|refresh_?token|session_?token)$/i, reason: 'Security token or API secret exposed in response', severity: 'CRITICAL' as const },
  { pattern: /^(internal_?id|is_?admin|admin|is_?superuser|role_?id)$/i, reason: 'Internal authorization/privilege property exposed in response', severity: 'HIGH' as const },
];

/**
 * Detects Excessive Data Exposure (OWASP API3:2023 - Broken Object Property Level Authorization)
 */
export class ExcessiveDataDetector {
  detect(endpoint: string, method: string, responsePayload: unknown): ExcessiveDataFinding[] {
    const findings: ExcessiveDataFinding[] = [];
    if (!responsePayload || typeof responsePayload !== 'object') return findings;

    const checkObject = (obj: Record<string, unknown>, pathPrefix = '') => {
      for (const [key, value] of Object.entries(obj)) {
        const fullPath = pathPrefix ? `${pathPrefix}.${key}` : key;

        for (const rule of SENSITIVE_KEY_PATTERNS) {
          if (rule.pattern.test(key) && value !== null && value !== undefined && value !== '') {
            findings.push({
              endpoint,
              method,
              exposedProperty: fullPath,
              sensitivityReason: rule.reason,
              ruleId: 'SEC-API-003',
              title: 'Excessive Data Exposure: Sensitive Field In Response',
              description: `Endpoint returned sensitive object property '${fullPath}'. ${rule.reason}.`,
              owaspApi: ['API3:2023'],
              cwe: ['CWE-200'],
              severity: rule.severity,
            });
          }
        }

        // Recursively inspect nested objects and arrays
        if (value && typeof value === 'object') {
          if (Array.isArray(value)) {
            for (const item of value.slice(0, 3)) {
              if (item && typeof item === 'object') checkObject(item as Record<string, unknown>, `${fullPath}[]`);
            }
          } else {
            checkObject(value as Record<string, unknown>, fullPath);
          }
        }
      }
    };

    checkObject(responsePayload as Record<string, unknown>);
    return findings;
  }
}
