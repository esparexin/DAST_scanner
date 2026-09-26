import crypto from 'node:crypto';
import type { ISecurityRule, RuleStatus, DetectionCategory, DetectionType } from '@securityscan/contracts';

export { PASSIVE_RULES, ACTIVE_RULES } from './rules-data.js';

export function computeRuleHash(rule: Partial<ISecurityRule>): string {
  const norm = {
    id: rule.id,
    name: rule.name,
    description: rule.description,
    category: rule.category,
    type: rule.type,
    severity: rule.severity,
    confidence: rule.confidence,
    cwe: [...(rule.cwe ?? [])].sort(),
    owasp: [...(rule.owasp ?? [])].sort(),
    apiOwasp: [...(rule.apiOwasp ?? [])].sort(),
    wstg: [...(rule.wstg ?? [])].sort(),
    asvs: [...(rule.asvs ?? [])].sort(),
    remediation: rule.remediation,
  };
  return crypto.createHash('sha256').update(JSON.stringify(norm)).digest('hex');
}

export class SecurityRuleRegistry {
  private rules: Map<string, ISecurityRule> = new Map();

  register(rule: ISecurityRule): void {
    const versionedRule: ISecurityRule = {
      ...rule,
      ruleVersion: rule.ruleVersion ?? '1.0.0',
      status: rule.status ?? (rule.enabled ? 'ACTIVE' : 'DISABLED'),
      contentHash: rule.contentHash ?? computeRuleHash(rule),
      createdAt: rule.createdAt ?? new Date().toISOString(),
      updatedAt: rule.updatedAt ?? new Date().toISOString(),
    };
    this.rules.set(versionedRule.id, versionedRule);
  }

  get(id: string): ISecurityRule | undefined {
    return this.rules.get(id);
  }

  getAll(): ISecurityRule[] {
    return Array.from(this.rules.values());
  }

  getByCategory(category: DetectionCategory): ISecurityRule[] {
    return this.getAll().filter((r) => r.category === category);
  }

  getByType(type: DetectionType): ISecurityRule[] {
    return this.getAll().filter((r) => r.type === type);
  }

  getByStatus(status: RuleStatus): ISecurityRule[] {
    return this.getAll().filter((r) => r.status === status);
  }

  deprecate(id: string): ISecurityRule | undefined {
    const existing = this.rules.get(id);
    if (!existing) return undefined;
    const deprecated: ISecurityRule = {
      ...existing,
      status: 'DEPRECATED',
      enabled: false,
      deprecatedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.rules.set(id, deprecated);
    return deprecated;
  }
}
