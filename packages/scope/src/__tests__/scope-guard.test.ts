import { describe, it, expect } from 'vitest';
import { ScopeGuard } from '../scope-guard.js';
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

describe('ScopeGuard', () => {
  describe('validate', () => {
    it('returns no errors for valid config', () => {
      const errors = ScopeGuard.validate(createConfig());
      expect(errors).toHaveLength(0);
    });

    it('returns error when not authorized', () => {
      const errors = ScopeGuard.validate(createConfig({ authorized: false }));
      expect(errors).toContainEqual(expect.stringContaining('not authorized'));
    });

    it('returns error when no allowed hosts', () => {
      const errors = ScopeGuard.validate(createConfig({ allowedHosts: [] }));
      expect(errors).toContainEqual(expect.stringContaining('allowed host'));
    });

    it('returns error when missing scanId', () => {
      const errors = ScopeGuard.validate(createConfig({ scanId: '' }));
      expect(errors).toContainEqual(expect.stringContaining('Scan ID'));
    });

    it('returns error for overlapping allowed/excluded hosts', () => {
      const errors = ScopeGuard.validate(
        createConfig({
          allowedHosts: ['example.com'],
          excludedHosts: ['example.com'],
        }),
      );
      expect(errors).toContainEqual(expect.stringContaining('both allowed and excluded'));
    });

    it('returns multiple errors', () => {
      const errors = ScopeGuard.validate(
        createConfig({
          authorized: false,
          allowedHosts: [],
          scanId: '',
        }),
      );
      expect(errors.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('validateOrThrow', () => {
    it('does not throw for valid config', () => {
      expect(() => ScopeGuard.validateOrThrow(createConfig())).not.toThrow();
    });

    it('throws for invalid config', () => {
      expect(() =>
        ScopeGuard.validateOrThrow(createConfig({ authorized: false })),
      ).toThrow('Scope validation failed');
    });
  });

  describe('createValidator', () => {
    it('creates validator for valid config', () => {
      const validator = ScopeGuard.createValidator(createConfig());
      expect(validator).toBeDefined();
    });

    it('throws for invalid config', () => {
      expect(() =>
        ScopeGuard.createValidator(createConfig({ authorized: false })),
      ).toThrow();
    });
  });
});
