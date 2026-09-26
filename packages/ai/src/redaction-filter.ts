import type { AIAnalysisRequest } from './types.js';

const CREDIT_CARD_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;
const SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/g;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
const JWT_REGEX = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
const API_KEY_REGEX =
  /(?:api[_-]?key|apikey|secret|token|password|passwd|auth)[\s]*[=:]\s*['"]?([A-Za-z0-9_\-/.+=]{16,})['"]?/gi;

export class PreAiRedactionFilter {
  private redactedFields: string[] = [];

  static redact(input: string): string;
  static redact(input: AIAnalysisRequest): AIAnalysisRequest;
  static redact(input: string | AIAnalysisRequest): string | AIAnalysisRequest {
    if (typeof input === 'string') {
      let cleaned = input;
      cleaned = cleaned.replace(CREDIT_CARD_REGEX, '[REDACTED_BY_AI_GATE]');
      cleaned = cleaned.replace(SSN_REGEX, '[REDACTED_BY_AI_GATE]');
      cleaned = cleaned.replace(EMAIL_REGEX, '[REDACTED_BY_AI_GATE]');
      cleaned = cleaned.replace(JWT_REGEX, '[REDACTED_BY_AI_GATE]');
      cleaned = cleaned.replace(API_KEY_REGEX, '$1[REDACTED_BY_AI_GATE]');
      return cleaned;
    }

    const serialized = JSON.stringify(input);
    let cleaned = serialized;
    cleaned = cleaned.replace(CREDIT_CARD_REGEX, '[REDACTED_BY_AI_GATE]');
    cleaned = cleaned.replace(SSN_REGEX, '[REDACTED_BY_AI_GATE]');
    cleaned = cleaned.replace(EMAIL_REGEX, '[REDACTED_BY_AI_GATE]');
    cleaned = cleaned.replace(JWT_REGEX, '[REDACTED_BY_AI_GATE]');
    cleaned = cleaned.replace(API_KEY_REGEX, '$1[REDACTED_BY_AI_GATE]');
    return JSON.parse(cleaned);
  }

  redact(request: AIAnalysisRequest): AIAnalysisRequest {
    return PreAiRedactionFilter.redact(request);
  }

  /**
   * Redact sensitive parts of a URL before sending to AI context.
   * Strips userinfo, query parameters with sensitive names, and path segments containing UUIDs/tokens.
   */
  redactUrl(url: string): string {
    try {
      const parsed = new URL(url);
      // Remove userinfo
      parsed.username = '';
      parsed.password = '';
      // Redact sensitive query params
      const sensitiveParamNames = /(?:token|key|secret|password|auth|session|api_key|apikey)/i;
      for (const [name] of [...parsed.searchParams.entries()]) {
        if (sensitiveParamNames.test(name)) {
          parsed.searchParams.set(name, '[REDACTED]');
        }
      }
      return parsed.toString().replace(/%5BREDACTED%5D/g, '[REDACTED]');
    } catch {
      return '[REDACTED_URL]';
    }
  }

  getRedactedFieldNames(): string[] {
    return [...this.redactedFields];
  }
}
