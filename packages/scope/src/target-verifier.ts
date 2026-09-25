import { randomBytes, createHash } from 'node:crypto';

export interface OwnershipChallenge {
  targetId: string;
  token: string;
  wellKnownPath: string;
  expectedContent: string;
  dnsRecordName: string;
  dnsExpectedValue: string;
  expiresAt: Date;
}

export interface VerificationResult {
  verified: boolean;
  method: 'HTTP_CHALLENGE' | 'DNS_TXT';
  details: string;
}

/**
 * Verifies domain ownership before a target can be marked AUTHORIZED.
 * Ensures tests can only be run against infrastructure owned/controlled by the operator.
 */
export class TargetOwnershipVerifier {
  static generateChallenge(targetId: string, hostname: string): OwnershipChallenge {
    const token = randomBytes(24).toString('hex');
    const hashed = createHash('sha256').update(`${targetId}:${token}`).digest('hex');

    return {
      targetId,
      token,
      wellKnownPath: `/.well-known/securityscan-challenge.txt`,
      expectedContent: `securityscan-verification=${hashed}`,
      dnsRecordName: `_securityscan-challenge.${hostname}`,
      dnsExpectedValue: hashed,
      expiresAt: new Date(Date.now() + 24 * 3600 * 1000), // 24 hours validity
    };
  }

  /**
   * Verify HTTP challenge response content
   */
  static verifyHttpChallenge(actualContent: string, challenge: OwnershipChallenge): VerificationResult {
    const trimmed = actualContent.trim();
    if (trimmed.includes(challenge.expectedContent)) {
      return {
        verified: true,
        method: 'HTTP_CHALLENGE',
        details: 'Challenge file successfully verified at /.well-known/securityscan-challenge.txt',
      };
    }
    return {
      verified: false,
      method: 'HTTP_CHALLENGE',
      details: 'Challenge file content did not match expected verification token',
    };
  }
}
