import { describe, it, expect } from 'vitest';
import { SecurityRuleRegistry, PASSIVE_RULES, ACTIVE_RULES, computeRuleHash } from '../registry.js';
import { DetectionCategory, DetectionType } from '@securityscan/contracts';

describe('SecurityRuleRegistry', () => {
  it('loads all pre-defined passive rules', () => {
    const registry = new SecurityRuleRegistry();
    for (const rule of PASSIVE_RULES) {
      registry.register(rule);
    }
    expect(registry.getAll()).toHaveLength(PASSIVE_RULES.length);
    expect(registry.getByType(DetectionType.PASSIVE)).toHaveLength(PASSIVE_RULES.length);
  });

  it('retrieves rule by ID and verifies versioning metadata', () => {
    const registry = new SecurityRuleRegistry();
    for (const rule of PASSIVE_RULES) {
      registry.register(rule);
    }
    const hstsRule = registry.get('SEC-HDR-001');
    expect(hstsRule).toBeDefined();
    expect(hstsRule?.name).toContain('Strict-Transport-Security');
    expect(hstsRule?.cwe).toContain('CWE-319');
    expect(hstsRule?.ruleVersion).toBe('1.0.0');
    expect(hstsRule?.status).toBe('ACTIVE');
    expect(hstsRule?.contentHash).toBeDefined();
    expect(hstsRule?.contentHash?.length).toBe(64);
  });

  it('filters rules by category', () => {
    const registry = new SecurityRuleRegistry();
    for (const rule of [...PASSIVE_RULES, ...ACTIVE_RULES]) {
      registry.register(rule);
    }
    const misconfigRules = registry.getByCategory(DetectionCategory.MISCONFIGURATION);
    expect(misconfigRules.length).toBeGreaterThan(0);
    expect(misconfigRules.every((r) => r.category === DetectionCategory.MISCONFIGURATION)).toBe(true);
  });

  it('computes deterministic contentHash for rules', () => {
    const hash1 = computeRuleHash(PASSIVE_RULES[0]!);
    const hash2 = computeRuleHash(PASSIVE_RULES[0]!);
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64);
  });

  it('filters rules by status and deprecates rules cleanly', () => {
    const registry = new SecurityRuleRegistry();
    for (const rule of PASSIVE_RULES) {
      registry.register(rule);
    }
    expect(registry.getByStatus('ACTIVE').length).toBe(PASSIVE_RULES.length);
    expect(registry.getByStatus('DEPRECATED')).toHaveLength(0);

    const deprecated = registry.deprecate('SEC-HDR-001');
    expect(deprecated).toBeDefined();
    expect(deprecated?.status).toBe('DEPRECATED');
    expect(deprecated?.enabled).toBe(false);
    expect(deprecated?.deprecatedAt).toBeDefined();

    expect(registry.getByStatus('DEPRECATED')).toHaveLength(1);
    expect(registry.getByStatus('ACTIVE').length).toBe(PASSIVE_RULES.length - 1);
  });
});
