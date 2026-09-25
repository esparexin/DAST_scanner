import { describe, it, expect } from 'vitest';
import { TargetOwnershipVerifier } from '../target-verifier.js';

describe('TargetOwnershipVerifier', () => {
  it('generates challenge with valid well-known path and DNS records', () => {
    const challenge = TargetOwnershipVerifier.generateChallenge('target-123', 'api.corp.com');
    expect(challenge.targetId).toBe('target-123');
    expect(challenge.wellKnownPath).toBe('/.well-known/securityscan-challenge.txt');
    expect(challenge.expectedContent).toContain('securityscan-verification=');
    expect(challenge.dnsRecordName).toBe('_securityscan-challenge.api.corp.com');
  });

  it('verifies valid HTTP challenge response', () => {
    const challenge = TargetOwnershipVerifier.generateChallenge('target-123', 'api.corp.com');
    const result = TargetOwnershipVerifier.verifyHttpChallenge(challenge.expectedContent, challenge);
    expect(result.verified).toBe(true);
    expect(result.method).toBe('HTTP_CHALLENGE');
  });

  it('rejects mismatched challenge response', () => {
    const challenge = TargetOwnershipVerifier.generateChallenge('target-123', 'api.corp.com');
    const result = TargetOwnershipVerifier.verifyHttpChallenge('random-wrong-content', challenge);
    expect(result.verified).toBe(false);
  });
});
