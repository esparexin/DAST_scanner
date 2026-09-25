import { describe, it, expect } from 'vitest';
import { ScopeValidator } from '../scope-validator.js';
import { ScopeValidationResult } from '@securityscan/contracts';
import type { IScopeConfig } from '@securityscan/contracts';

function createConfig(overrides: Partial<IScopeConfig> = {}): IScopeConfig {
  return {
    scanId: 'scan-1',
    targetId: 'target-1',
    projectId: 'project-1',
    authorized: true,
    allowedHosts: ['example.com'],
    excludedHosts: [],
    allowedPaths: [],
    excludedPaths: [],
    maxRequestsPerSecond: 10,
    maxConcurrency: 5,
    maxRequests: 1000,
    maxCrawlDepth: 5,
    maxResponseSize: 10 * 1024 * 1024,
    maxScanDuration: 3600,
    timeoutPerRequest: 30,
    ...overrides,
  };
}

describe('ScopeValidator', () => {
  describe('constructor', () => {
    it('throws if not authorized', () => {
      expect(() => new ScopeValidator(createConfig({ authorized: false }))).toThrow(
        'not authorized',
      );
    });

    it('throws if no allowed hosts', () => {
      expect(() => new ScopeValidator(createConfig({ allowedHosts: [] }))).toThrow(
        'No allowed hosts',
      );
    });

    it('creates successfully with valid config', () => {
      const validator = new ScopeValidator(createConfig());
      expect(validator).toBeDefined();
    });
  });

  describe('validate', () => {
    it('allows requests to allowed hosts', () => {
      const validator = new ScopeValidator(createConfig());
      const result = validator.validate('https://example.com/api/test');
      expect(result.result).toBe(ScopeValidationResult.ALLOWED);
    });

    it('blocks requests to disallowed hosts', () => {
      const validator = new ScopeValidator(createConfig());
      const result = validator.validate('https://evil.com/api/test');
      expect(result.result).toBe(ScopeValidationResult.BLOCKED_HOST);
    });

    it('blocks requests to excluded hosts', () => {
      const validator = new ScopeValidator(
        createConfig({
          allowedHosts: ['*.example.com'],
          excludedHosts: ['admin.example.com'],
        }),
      );
      const result = validator.validate('https://admin.example.com/api/test');
      expect(result.result).toBe(ScopeValidationResult.BLOCKED_EXCLUDED);
    });

    it('supports wildcard host matching', () => {
      const validator = new ScopeValidator(
        createConfig({ allowedHosts: ['*.example.com'] }),
      );
      expect(validator.validate('https://api.example.com/test').result).toBe(
        ScopeValidationResult.ALLOWED,
      );
      expect(validator.validate('https://sub.api.example.com/test').result).toBe(
        ScopeValidationResult.ALLOWED,
      );
      expect(validator.validate('https://other.com/test').result).toBe(
        ScopeValidationResult.BLOCKED_HOST,
      );
    });

    it('enforces allowed paths', () => {
      const validator = new ScopeValidator(
        createConfig({ allowedPaths: ['/api/'] }),
      );
      expect(validator.validate('https://example.com/api/test').result).toBe(
        ScopeValidationResult.ALLOWED,
      );
      expect(validator.validate('https://example.com/admin/test').result).toBe(
        ScopeValidationResult.BLOCKED_PATH,
      );
    });

    it('enforces excluded paths', () => {
      const validator = new ScopeValidator(
        createConfig({ excludedPaths: ['/admin'] }),
      );
      expect(validator.validate('https://example.com/api/test').result).toBe(
        ScopeValidationResult.ALLOWED,
      );
      expect(validator.validate('https://example.com/admin/users').result).toBe(
        ScopeValidationResult.BLOCKED_PATH,
      );
    });

    it('blocks when request limit is exceeded', () => {
      const validator = new ScopeValidator(createConfig({ maxRequests: 2 }));
      validator.recordRequest();
      validator.recordRequest();
      const result = validator.validate('https://example.com/test');
      expect(result.result).toBe(ScopeValidationResult.REQUEST_LIMIT_EXCEEDED);
    });

    it('blocks invalid URLs', () => {
      const validator = new ScopeValidator(createConfig());
      const result = validator.validate('not-a-url');
      expect(result.result).toBe(ScopeValidationResult.BLOCKED_HOST);
    });

    it('blocks after cancellation', () => {
      const validator = new ScopeValidator(createConfig());
      validator.cancel();
      const result = validator.validate('https://example.com/test');
      expect(result.result).toBe(ScopeValidationResult.SCAN_CANCELLED);
    });
  });

  describe('validateOrThrow', () => {
    it('does not throw for valid requests', () => {
      const validator = new ScopeValidator(createConfig());
      expect(() =>
        validator.validateOrThrow('https://example.com/test'),
      ).not.toThrow();
    });

    it('throws for invalid requests', () => {
      const validator = new ScopeValidator(createConfig());
      expect(() =>
        validator.validateOrThrow('https://evil.com/test'),
      ).toThrow();
    });
  });

  describe('getStats', () => {
    it('tracks request count', () => {
      const validator = new ScopeValidator(createConfig());
      expect(validator.getStats().requestCount).toBe(0);
      validator.recordRequest();
      validator.recordRequest();
      expect(validator.getStats().requestCount).toBe(2);
    });

    it('tracks cancellation state', () => {
      const validator = new ScopeValidator(createConfig());
      expect(validator.getStats().cancelled).toBe(false);
      validator.cancel();
      expect(validator.getStats().cancelled).toBe(true);
    });
  });
});
