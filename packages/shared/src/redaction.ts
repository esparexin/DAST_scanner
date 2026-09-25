import { SENSITIVE_HEADER_PATTERNS, SENSITIVE_BODY_PATTERNS } from '@securityscan/contracts';

/**
 * Redact sensitive HTTP headers from a headers object.
 * Returns a new object with sensitive values replaced.
 */
export function redactSensitiveHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const redacted: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    const isSensitive = SENSITIVE_HEADER_PATTERNS.some((pattern) =>
      pattern.test(key),
    );
    redacted[key] = isSensitive ? '[REDACTED]' : value;
  }

  return redacted;
}

/**
 * Redact sensitive values from a string body.
 * Replaces values in key-value patterns where the key matches sensitive patterns.
 */
export function redactSensitiveBody(body: string): string {
  let redacted = body;

  for (const pattern of SENSITIVE_BODY_PATTERNS) {
    // Match JSON-style: "key": "value"
    redacted = redacted.replace(
      new RegExp(`("${pattern.source}"\\s*:\\s*")([^"]*)(")`  , 'gi'),
      '$1[REDACTED]$3',
    );

    // Match form-style: key=value
    redacted = redacted.replace(
      new RegExp(`(${pattern.source}=)([^&\\s]*)`, 'gi'),
      '$1[REDACTED]',
    );
  }

  return redacted;
}
