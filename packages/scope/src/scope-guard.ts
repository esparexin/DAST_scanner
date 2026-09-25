import type { IScopeConfig } from '@securityscan/contracts';
import { ScopeValidator } from './scope-validator.js';
import { ScopeError } from '@securityscan/shared';

/**
 * High-level scope guard that validates a scope configuration is complete
 * and meets all safety requirements before allowing a scan to start.
 * 
 * This is the pre-scan validation gate.
 */
export class ScopeGuard {
  /**
   * Validate that a scope configuration is safe and complete.
   * Returns validation errors, or empty array if valid.
   */
  static validate(config: IScopeConfig): string[] {
    const errors: string[] = [];

    if (!config.authorized) {
      errors.push('Target is not authorized. Set authorization to AUTHORIZED before scanning.');
    }

    if (!config.allowedHosts || config.allowedHosts.length === 0) {
      errors.push('At least one allowed host must be defined.');
    }

    if (!config.scanId) {
      errors.push('Scan ID is required.');
    }

    if (!config.targetId) {
      errors.push('Target ID is required.');
    }

    if (!config.projectId) {
      errors.push('Project ID is required.');
    }

    if (config.maxRequestsPerSecond <= 0) {
      errors.push('maxRequestsPerSecond must be positive.');
    }

    if (config.maxConcurrency <= 0) {
      errors.push('maxConcurrency must be positive.');
    }

    if (config.maxRequests <= 0) {
      errors.push('maxRequests must be positive.');
    }

    if (config.maxScanDuration <= 0) {
      errors.push('maxScanDuration must be positive.');
    }

    // Check for overlap between allowed and excluded hosts
    if (config.allowedHosts && config.excludedHosts) {
      for (const host of config.allowedHosts) {
        if (config.excludedHosts.includes(host)) {
          errors.push(`Host '${host}' appears in both allowed and excluded lists.`);
        }
      }
    }

    return errors;
  }

  /**
   * Validate and throw if invalid.
   */
  static validateOrThrow(config: IScopeConfig): void {
    const errors = ScopeGuard.validate(config);
    if (errors.length > 0) {
      throw new ScopeError(
        `Scope validation failed:\n${errors.map((e) => `  - ${e}`).join('\n')}`,
      );
    }
  }

  /**
   * Create a ScopeValidator from a validated config.
   * Throws if config is invalid.
   */
  static createValidator(config: IScopeConfig): ScopeValidator {
    ScopeGuard.validateOrThrow(config);
    return new ScopeValidator(config);
  }
}
