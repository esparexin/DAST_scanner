import { describe, it, expect, vi } from 'vitest';
import { JwtAnalyzer, JwtSecurityChecks } from '../index.js';
import { HttpMethod } from '@securityscan/contracts';

describe('JwtAnalyzer', () => {
  const sampleHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const samplePayload = Buffer.from(JSON.stringify({ sub: 'user-42', role: 'user', exp: 1999999999 })).toString('base64url');
  const sampleToken = `${sampleHeader}.${samplePayload}.validSig123`;

  it('parses valid token parts correctly', () => {
    const parsed = JwtAnalyzer.parse(sampleToken);
    expect(parsed).not.toBeNull();
    expect(parsed?.header['alg']).toBe('HS256');
    expect(parsed?.payload['sub']).toBe('user-42');
  });

  it('creates none-algorithm mutant correctly', () => {
    const parsed = JwtAnalyzer.parse(sampleToken)!;
    const noneToken = JwtAnalyzer.createNoneAlgorithmMutant(parsed);
    const reparsed = JwtAnalyzer.parse(noneToken);
    expect(reparsed?.header['alg']).toBe('none');
    expect(noneToken.endsWith('.')).toBe(true);
  });

  it('creates invalid signature mutant correctly', () => {
    const parsed = JwtAnalyzer.parse(sampleToken)!;
    const mutant = JwtAnalyzer.createInvalidSignatureMutant(parsed);
    expect(mutant).toContain('invalidSignatureCanary123');
  });

  it('creates expired token mutant correctly', () => {
    const parsed = JwtAnalyzer.parse(sampleToken)!;
    const expiredToken = JwtAnalyzer.createExpiredTokenMutant(parsed);
    const reparsed = JwtAnalyzer.parse(expiredToken);
    expect(Number(reparsed?.payload['exp'])).toBeLessThan(Date.now() / 1000);
  });
});

describe('JwtSecurityChecks', () => {
  const sampleHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const samplePayload = Buffer.from(JSON.stringify({ sub: 'user-42', role: 'user' })).toString('base64url');
  const sampleToken = `${sampleHeader}.${samplePayload}.validSig123`;

  it('detects none-algorithm acceptance vulnerability', async () => {
    const checks = JwtSecurityChecks.getChecks(sampleToken);
    const noneCheck = checks.find((c) => c.rule.id === 'SEC-JWT-001')!;

    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200, // Vulnerable server accepted none-algorithm token!
        headers: { 'content-type': 'application/json' },
        body: '{"data": "secret"}',
        responseTime: 20,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/api/profile', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const results = await noneCheck.run(ctx);
    expect(results).toHaveLength(1);
    expect(results[0]?.ruleId).toBe('SEC-JWT-001');
    expect(results[0]?.severity).toBe('CRITICAL');
  });

  it('passes when server rejects none-algorithm token with 401', async () => {
    const checks = JwtSecurityChecks.getChecks(sampleToken);
    const noneCheck = checks.find((c) => c.rule.id === 'SEC-JWT-001')!;

    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 401, // Secure server rejected unsigned token
        headers: {},
        body: 'Unauthorized',
        responseTime: 15,
      }),
    };

    const ctx: any = {
      endpoint: { url: 'https://example.com/api/profile', method: HttpMethod.GET },
      httpClient: mockClient,
    };

    const results = await noneCheck.run(ctx);
    expect(results).toHaveLength(0);
  });
});
