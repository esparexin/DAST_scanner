import { describe, it, expect } from 'vitest';
import { CreateProjectSchema } from '../schemas/project.schema.js';
import { CreateTargetSchema } from '../schemas/target.schema.js';
import { CreateScanSchema } from '../schemas/scan.schema.js';
import { ScopeSchema } from '../schemas/scope.schema.js';
import { ScanProfile, TargetEnvironment } from '../enums.js';

describe('CreateProjectSchema', () => {
  it('validates valid project', () => {
    const result = CreateProjectSchema.safeParse({
      name: 'Test Project',
      description: 'A test project',
    });
    expect(result.success).toBe(true);
  });

  it('rejects empty name', () => {
    const result = CreateProjectSchema.safeParse({ name: '' });
    expect(result.success).toBe(false);
  });

  it('provides default description', () => {
    const result = CreateProjectSchema.parse({ name: 'Test' });
    expect(result.description).toBe('');
  });
});

describe('ScopeSchema', () => {
  it('validates valid scope', () => {
    const result = ScopeSchema.safeParse({
      allowedHosts: ['example.com'],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.maxRequestsPerSecond).toBe(10);
      expect(result.data.maxConcurrency).toBe(5);
    }
  });

  it('rejects empty allowed hosts', () => {
    const result = ScopeSchema.safeParse({
      allowedHosts: [],
    });
    expect(result.success).toBe(false);
  });

  it('rejects invalid hostname', () => {
    const result = ScopeSchema.safeParse({
      allowedHosts: ['http://example.com'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects rate limit over maximum', () => {
    const result = ScopeSchema.safeParse({
      allowedHosts: ['example.com'],
      maxRequestsPerSecond: 999,
    });
    expect(result.success).toBe(false);
  });

  it('applies defaults', () => {
    const result = ScopeSchema.parse({
      allowedHosts: ['example.com'],
    });
    expect(result.excludedHosts).toEqual([]);
    expect(result.allowedPaths).toEqual([]);
    expect(result.excludedPaths).toEqual([]);
    expect(result.maxRequests).toBe(10000);
    expect(result.maxCrawlDepth).toBe(5);
    expect(result.maxScanDuration).toBe(3600);
    expect(result.timeoutPerRequest).toBe(30);
  });
});

describe('CreateTargetSchema', () => {
  it('validates valid target', () => {
    const result = CreateTargetSchema.safeParse({
      projectId: 'proj-1',
      name: 'Test Target',
      baseUrl: 'https://example.com',
      scope: {
        allowedHosts: ['example.com'],
      },
    });
    expect(result.success).toBe(true);
  });

  it('rejects invalid URL', () => {
    const result = CreateTargetSchema.safeParse({
      projectId: 'proj-1',
      name: 'Test',
      baseUrl: 'not-a-url',
      scope: { allowedHosts: ['example.com'] },
    });
    expect(result.success).toBe(false);
  });

  it('defaults environment to TESTING', () => {
    const result = CreateTargetSchema.parse({
      projectId: 'proj-1',
      name: 'Test',
      baseUrl: 'https://example.com',
      scope: { allowedHosts: ['example.com'] },
    });
    expect(result.environment).toBe(TargetEnvironment.TESTING);
  });
});

describe('CreateScanSchema', () => {
  it('validates valid scan', () => {
    const result = CreateScanSchema.safeParse({
      projectId: 'proj-1',
      targetId: 'target-1',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.profile).toBe(ScanProfile.WEB_STANDARD);
      expect(result.data.dryRun).toBe(false);
    }
  });

  it('rejects missing projectId', () => {
    const result = CreateScanSchema.safeParse({
      targetId: 'target-1',
    });
    expect(result.success).toBe(false);
  });
});
