import { describe, it, expect } from 'vitest';
import {
  CatalogOverrideManager,
  PayloadRegistry,
  loadDefaultCatalogs,
} from '../index.js';

describe('CatalogOverrideManager', () => {
  it('disables specific payload IDs via denylist', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);
    const initialCount = registry.getAll().filter((p) => p.status === 'ACTIVE').length;

    const result = CatalogOverrideManager.applyOverrides(registry, {
      ...CatalogOverrideManager.defaultOverrides(),
      disabledPayloadIds: ['PL-SQLI-ERR-001'],
    });

    expect(result.applied).toBe(1);
    expect(result.disabled).toContain('PL-SQLI-ERR-001');
    expect(registry.get('PL-SQLI-ERR-001')?.status).toBe('DISABLED');
    expect(registry.getAll().filter((p) => p.status === 'ACTIVE').length).toBe(initialCount - 1);
  });

  it('restricts to allowlist only when provided', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);
    const totalPayloads = registry.size();

    const result = CatalogOverrideManager.applyOverrides(registry, {
      ...CatalogOverrideManager.defaultOverrides(),
      allowedPayloadIds: ['PL-SQLI-ERR-001', 'PL-XSS-TAG-001'],
    });

    // Everything except the two allowed should be disabled
    expect(result.applied).toBe(totalPayloads - 2);
    expect(registry.get('PL-SQLI-ERR-001')?.status).toBe('ACTIVE');
    expect(registry.get('PL-XSS-TAG-001')?.status).toBe('ACTIVE');
    expect(registry.get('PL-PT-UNIX-001')?.status).toBe('DISABLED');
  });

  it('enforces safety level ceiling (production-safe)', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const result = CatalogOverrideManager.applyOverrides(
      registry,
      CatalogOverrideManager.productionSafeOverrides(),
    );

    // BOUNDED_ACTIVE payloads should be disabled, SAFE should remain
    const remaining = registry.getAll().filter((p) => p.status === 'ACTIVE');
    for (const p of remaining) {
      expect(p.safetyLevel).toBe('SAFE');
    }
    expect(result.applied).toBeGreaterThan(0);
  });

  it('disables entire categories', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);

    const result = CatalogOverrideManager.applyOverrides(registry, {
      ...CatalogOverrideManager.defaultOverrides(),
      disabledCategories: ['INJECTION'],
    });

    const injectionPayloads = registry.getAll().filter((p) => p.category === 'INJECTION');
    for (const p of injectionPayloads) {
      expect(p.status).toBe('DISABLED');
    }
    expect(result.applied).toBeGreaterThan(0);
  });

  it('default overrides leave everything active', () => {
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);
    const initialActive = registry.getAll().filter((p) => p.status === 'ACTIVE').length;

    const result = CatalogOverrideManager.applyOverrides(
      registry,
      CatalogOverrideManager.defaultOverrides(),
    );

    expect(result.applied).toBe(0);
    expect(registry.getAll().filter((p) => p.status === 'ACTIVE').length).toBe(initialActive);
  });
});
