/**
 * JWT Security Testing Engine
 * Inspects and constructs test token variants for algorithm confusion, none-algorithm, and exp claim validation.
 */

export interface ParsedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  rawToken: string;
}

export class JwtAnalyzer {
  static parse(token: string): ParsedJwt | null {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    try {
      const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
      return {
        header,
        payload,
        signature: parts[2]!,
        rawToken: token,
      };
    } catch {
      return null;
    }
  }

  /**
   * Build an "alg: none" mutant of the token (unsecured JWT testing)
   */
  static createNoneAlgorithmMutant(parsed: ParsedJwt): string {
    const header = { ...parsed.header, alg: 'none' };
    const b64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
    const b64Payload = Buffer.from(JSON.stringify(parsed.payload)).toString('base64url');
    return `${b64Header}.${b64Payload}.`;
  }

  /**
   * Build an expired token mutant
   */
  static createExpiredTokenMutant(parsed: ParsedJwt): string {
    const past = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    const payload = { ...parsed.payload, exp: past };
    const b64Header = Buffer.from(JSON.stringify(parsed.header)).toString('base64url');
    const b64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    // Keep original signature to test if server actually verifies exp before/with signature
    return `${b64Header}.${b64Payload}.${parsed.signature}`;
  }

  /**
   * Build an unsigned token mutant with invalid signature
   */
  static createInvalidSignatureMutant(parsed: ParsedJwt): string {
    const b64Header = Buffer.from(JSON.stringify(parsed.header)).toString('base64url');
    const b64Payload = Buffer.from(JSON.stringify(parsed.payload)).toString('base64url');
    return `${b64Header}.${b64Payload}.invalidSignatureCanary123`;
  }
}
