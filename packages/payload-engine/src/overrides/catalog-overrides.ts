import type { PayloadRegistry } from '../registry/payload-registry.js';
import type { IPayloadDefinition } from '../types/payload-definition.js';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('catalog-overrides');

export interface OrganizationOverrides {
  /** Payload IDs to explicitly disable (denylist) */
  disabledPayloadIds: string[];
  /** If non-empty, ONLY these payload IDs are allowed (allowlist takes precedence) */
  allowedPayloadIds: string[];
  /** Safety level ceiling: payloads above this level are disabled */
  maxSafetyLevel: 'SAFE' | 'BOUNDED_ACTIVE' | 'POTENTIALLY_DISRUPTIVE';
  /** Categories to skip entirely */
  disabledCategories: string[];
  /** Custom tags to exclude */
  excludeTags: string[];
}

const SAFETY_LEVEL_ORDER: Record<string, number> = {
  SAFE: 0,
  BOUNDED_ACTIVE: 1,
  POTENTIALLY_DISRUPTIVE: 2,
};

/**
 * Applies enterprise organization-level overrides to a PayloadRegistry.
 *
 * This allows security teams to:
 * - Disable specific payload IDs for compliance reasons
 * - Restrict to an explicit allowlist of approved payloads
 * - Set a safety-level ceiling (e.g. production environments = SAFE only)
 * - Disable entire vulnerability categories
 */
export class CatalogOverrideManager {
  static applyOverrides(
    registry: PayloadRegistry,
    overrides: OrganizationOverrides,
  ): { applied: number; disabled: string[] } {
    const all = registry.getAll();
    const disabledIds: string[] = [];
    let appliedCount = 0;

    const maxLevel = SAFETY_LEVEL_ORDER[overrides.maxSafetyLevel] ?? 2;

    for (const payload of all) {
      let shouldDisable = false;
      let reason = '';

      // 1. Denylist check
      if (overrides.disabledPayloadIds.includes(payload.id)) {
        shouldDisable = true;
        reason = 'explicitly disabled by organization denylist';
      }

      // 2. Allowlist check (if non-empty, only listed IDs are allowed)
      if (
        !shouldDisable &&
        overrides.allowedPayloadIds.length > 0 &&
        !overrides.allowedPayloadIds.includes(payload.id)
      ) {
        shouldDisable = true;
        reason = 'not in organization allowlist';
      }

      // 3. Safety level ceiling
      if (!shouldDisable) {
        const payloadLevel = SAFETY_LEVEL_ORDER[payload.safetyLevel] ?? 0;
        if (payloadLevel > maxLevel) {
          shouldDisable = true;
          reason = `safety level ${payload.safetyLevel} exceeds ceiling ${overrides.maxSafetyLevel}`;
        }
      }

      // 4. Category disable
      if (!shouldDisable && overrides.disabledCategories.includes(payload.category)) {
        shouldDisable = true;
        reason = `category ${payload.category} disabled by organization`;
      }

      if (shouldDisable) {
        // We mark the payload as DISABLED in-place
        const updated: IPayloadDefinition = { ...payload, status: 'DISABLED' };
        registry.register(updated);
        disabledIds.push(payload.id);
        appliedCount++;
        logger.info({ payloadId: payload.id, reason }, 'Payload disabled by organization override');
      }
    }

    return { applied: appliedCount, disabled: disabledIds };
  }

  /**
   * Create a default permissive override set (nothing disabled).
   */
  static defaultOverrides(): OrganizationOverrides {
    return {
      disabledPayloadIds: [],
      allowedPayloadIds: [],
      maxSafetyLevel: 'POTENTIALLY_DISRUPTIVE',
      disabledCategories: [],
      excludeTags: [],
    };
  }

  /**
   * Create a production-safe override set (only SAFE payloads allowed).
   */
  static productionSafeOverrides(): OrganizationOverrides {
    return {
      disabledPayloadIds: [],
      allowedPayloadIds: [],
      maxSafetyLevel: 'SAFE',
      disabledCategories: [],
      excludeTags: [],
    };
  }
}
