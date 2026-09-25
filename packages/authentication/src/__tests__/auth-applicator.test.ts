import { describe, it, expect } from 'vitest';
import { AuthApplicator } from '../auth-applicator.js';
import { AuthType } from '@securityscan/contracts';

describe('AuthApplicator', () => {
  const applicator = new AuthApplicator();

  it('applies bearer token', () => {
    const headers = applicator.apply(AuthType.JWT, { token: 'abc123' }, {});
    expect(headers['Authorization']).toBe('Bearer abc123');
  });

  it('applies API key', () => {
    const headers = applicator.apply(AuthType.API_KEY, { apiKeyHeader: 'X-Api-Key', apiKeyValue: 'key123' }, {});
    expect(headers['X-Api-Key']).toBe('key123');
  });

  it('applies cookies', () => {
    const headers = applicator.apply(AuthType.COOKIE_SESSION, { cookies: { session: 'abc', user: 'xyz' } }, {});
    expect(headers['Cookie']).toBe('session=abc; user=xyz');
  });

  it('applies custom headers', () => {
    const headers = applicator.apply(AuthType.CUSTOM_HEADER, { customHeaders: { 'X-Custom': 'value' } }, {});
    expect(headers['X-Custom']).toBe('value');
  });

  it('does nothing for NONE', () => {
    const headers = applicator.apply(AuthType.NONE, {}, { existing: 'val' });
    expect(Object.keys(headers)).toEqual(['existing']);
  });

  it('returns correct auth labels', () => {
    expect(applicator.getAuthLabel(AuthType.JWT, {})).toBe('bearer');
    expect(applicator.getAuthLabel(AuthType.API_KEY, { apiKeyHeader: 'X-Key' })).toBe('api-key:X-Key');
    expect(applicator.getAuthLabel(AuthType.NONE, {})).toBe('anonymous');
  });
});
