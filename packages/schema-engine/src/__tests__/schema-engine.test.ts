import { describe, it, expect } from 'vitest';
import { UndocumentedEndpointDetector, ExcessiveDataDetector } from '../index.js';
import { HttpMethod } from '@securityscan/contracts';

describe('UndocumentedEndpointDetector', () => {
  const detector = new UndocumentedEndpointDetector();
  const documented = [
    { path: '/api/v1/users', method: HttpMethod.GET, parameters: [], security: [] },
    { path: '/api/v1/users/{id}', method: HttpMethod.GET, parameters: [], security: [] },
  ];

  it('matches parameterized paths accurately', () => {
    const observed = [
      { path: '/api/v1/users', method: HttpMethod.GET, url: 'https://api.corp/api/v1/users' },
      { path: '/api/v1/users/42', method: HttpMethod.GET, url: 'https://api.corp/api/v1/users/42' },
    ];
    const findings = detector.detect(observed, documented as any);
    expect(findings).toHaveLength(0);
  });

  it('flags shadow and undocumented endpoints', () => {
    const observed = [
      { path: '/api/v1/internal/debug', method: HttpMethod.GET, url: 'https://api.corp/api/v1/internal/debug' },
      { path: '/api/v1/payments', method: HttpMethod.POST, url: 'https://api.corp/api/v1/payments' },
    ];
    const findings = detector.detect(observed, documented as any);
    expect(findings).toHaveLength(2);
    expect(findings.some((f) => f.observedPath === '/api/v1/internal/debug' && f.severity === 'HIGH')).toBe(true);
    expect(findings.some((f) => f.observedPath === '/api/v1/payments')).toBe(true);
  });
});

describe('ExcessiveDataDetector', () => {
  const detector = new ExcessiveDataDetector();

  it('detects exposed password and private keys in response body', () => {
    const payload = {
      user: {
        id: 101,
        name: 'Alice',
        password_hash: '$2b$12$e8iZ...', 
      },
    };
    const findings = detector.detect('/api/users/101', 'GET', payload);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.exposedProperty).toBe('user.password_hash');
    expect(findings[0]?.severity).toBe('CRITICAL');
  });

  it('detects exposed privilege attributes', () => {
    const payload = {
      id: 1,
      email: 'bob@example.com',
      is_admin: true,
    };
    const findings = detector.detect('/api/profile', 'GET', payload);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.exposedProperty).toBe('is_admin');
    expect(findings[0]?.severity).toBe('HIGH');
  });
});
