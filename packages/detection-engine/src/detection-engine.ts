import type { SecurityCheck, CheckContext, CheckResult } from './types.js';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('detection-engine');

export class DetectionEngine {
  private readonly checks: SecurityCheck[] = [];

  register(check: SecurityCheck): void {
    this.checks.push(check);
    logger.debug({ ruleId: check.rule.id, name: check.rule.name }, 'Check registered');
  }

  registerAll(checks: SecurityCheck[]): void {
    for (const check of checks) {
      this.register(check);
    }
  }

  getChecks(category?: string): SecurityCheck[] {
    if (!category) return this.checks.filter((c) => c.rule.enabled);
    return this.checks.filter((c) => c.rule.enabled && c.rule.category === category);
  }

  async runAll(context: CheckContext, categories?: string[]): Promise<CheckResult[]> {
    const checks = categories
      ? this.checks.filter((c) => c.rule.enabled && categories.includes(c.rule.category))
      : this.checks.filter((c) => c.rule.enabled);

    const results: CheckResult[] = [];

    for (const check of checks) {
      try {
        logger.debug({ ruleId: check.rule.id }, 'Running check');
        const checkResults = await check.run(context);
        results.push(...checkResults);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        logger.error({ ruleId: check.rule.id, error: message }, 'Check failed');
      }
    }

    return results;
  }
}
