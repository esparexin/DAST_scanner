import { describe, it, expect } from 'vitest';
import { SecurityRuleRegistry, PASSIVE_RULES, ACTIVE_RULES } from '../registry.js';
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

  it('retrieves rule by ID', () => {
    const registry = new SecurityRuleRegistry();
    for (const rule of PASSIVE_RULES) {
      registry.register(rule);
    }
    const hstsRule = registry.get('SEC-HDR-001');
    expect(hstsRule).toBeDefined();
    expect(hstsRule?.name).toContain('Strict-Transport-Security');
    expect(hstsRule?.cwe).toContain('CWE-319');
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
});
