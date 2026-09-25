import { describe, it, expect } from 'vitest';
import { redactSensitiveHeaders, redactSensitiveBody } from '../redaction.js';

describe('redactSensitiveHeaders', () => {
  it('redacts Authorization header', () => {
    const result = redactSensitiveHeaders({
      Authorization: 'Bearer secret-token',
      'Content-Type': 'application/json',
    });
    expect(result['Authorization']).toBe('[REDACTED]');
    expect(result['Content-Type']).toBe('application/json');
  });

  it('redacts Cookie header', () => {
    const result = redactSensitiveHeaders({
      Cookie: 'session=abc123',
    });
    expect(result['Cookie']).toBe('[REDACTED]');
  });

  it('redacts Set-Cookie header', () => {
    const result = redactSensitiveHeaders({
      'Set-Cookie': 'session=abc123; HttpOnly',
    });
    expect(result['Set-Cookie']).toBe('[REDACTED]');
  });

  it('redacts X-Api-Key header', () => {
    const result = redactSensitiveHeaders({
      'X-Api-Key': 'my-secret-key',
    });
    expect(result['X-Api-Key']).toBe('[REDACTED]');
  });

  it('preserves non-sensitive headers', () => {
    const result = redactSensitiveHeaders({
      'Content-Type': 'application/json',
      Accept: 'text/html',
      'User-Agent': 'SecurityScan/0.1.0',
    });
    expect(result['Content-Type']).toBe('application/json');
    expect(result['Accept']).toBe('text/html');
    expect(result['User-Agent']).toBe('SecurityScan/0.1.0');
  });
});

describe('redactSensitiveBody', () => {
  it('redacts JSON password fields', () => {
    const body = '{"username": "admin", "password": "secret123"}';
    const result = redactSensitiveBody(body);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('secret123');
    expect(result).toContain('admin');
  });

  it('redacts form-encoded password fields', () => {
    const body = 'username=admin&password=secret123';
    const result = redactSensitiveBody(body);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('secret123');
  });

  it('preserves non-sensitive content', () => {
    const body = '{"name": "John", "email": "john@example.com"}';
    const result = redactSensitiveBody(body);
    expect(result).toBe(body);
  });
});
