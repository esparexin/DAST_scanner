import type { IPayloadDefinition, ApplicableParameterType, ParameterLocation, TargetReflectionContext, PayloadSafetyLevel } from '../types/payload-definition.js';
import type { PayloadRegistry } from '../registry/payload-registry.js';
import { DetectionCategory, ScanProfile } from '@securityscan/contracts';

export interface ParameterSelectionContext {
  name: string;
  location: ParameterLocation;
  type: ApplicableParameterType;
  reflectionContext?: TargetReflectionContext;
  category?: DetectionCategory;
  scanProfile: ScanProfile;
  maxProbesPerParam?: number;
  serverEngine?: string;
}

export class PayloadSelector {
  private readonly registry: PayloadRegistry;

  constructor(registry: PayloadRegistry) {
    this.registry = registry;
  }

  /**
   * Select a small, highly relevant, calibrated subset of payloads for a specific parameter
   */
  select(context: ParameterSelectionContext): IPayloadDefinition[] {
    const index = this.registry.getIndex();

    const candidateIds = index.queryCandidateIds({
      category: context.category,
      paramType: context.type,
      location: context.location,
      context: context.reflectionContext,
    });

    const maxSafety = this.getMaxSafetyLevelForProfile(context.scanProfile);
    const candidateList: IPayloadDefinition[] = [];

    for (const id of candidateIds) {
      const p = index.get(id);
      if (!p || p.status !== 'ACTIVE') continue;

      // Filter by safety level permitted by the scan profile
      if (!this.isSafetyPermitted(p.safetyLevel, maxSafety)) continue;

      // Optional server engine filter
      if (context.serverEngine && p.applicability.serverEngines && p.applicability.serverEngines.length > 0) {
        if (!p.applicability.serverEngines.includes(context.serverEngine)) continue;
      }

      candidateList.push(p);
    }

    // Prioritize and cap count per parameter
    const limit = context.maxProbesPerParam ?? this.getDefaultLimitForProfile(context.scanProfile);
    return candidateList.slice(0, limit);
  }

  private getMaxSafetyLevelForProfile(profile: ScanProfile): PayloadSafetyLevel {
    switch (profile) {
      case ScanProfile.PASSIVE:
        return 'SAFE';
      case ScanProfile.QUICK:
      case ScanProfile.PRODUCTION_SAFE:
        return 'SAFE';
      case ScanProfile.WEB_STANDARD:
      case ScanProfile.API_STANDARD:
      case ScanProfile.AUTHENTICATED:
      case ScanProfile.AUTHORIZATION:
      case ScanProfile.CICD:
        return 'BOUNDED_ACTIVE';
      case ScanProfile.FULL_ASSESSMENT:
      case ScanProfile.SECURITY_LAB:
      default:
        return 'POTENTIALLY_DISRUPTIVE';
    }
  }

  private isSafetyPermitted(payloadLevel: PayloadSafetyLevel, maxPermitted: PayloadSafetyLevel): boolean {
    const levels: PayloadSafetyLevel[] = ['SAFE', 'BOUNDED_ACTIVE', 'POTENTIALLY_DISRUPTIVE'];
    return levels.indexOf(payloadLevel) <= levels.indexOf(maxPermitted);
  }

  private getDefaultLimitForProfile(profile: ScanProfile): number {
    switch (profile) {
      case ScanProfile.PASSIVE:
        return 0;
      case ScanProfile.QUICK:
        return 2;
      case ScanProfile.PRODUCTION_SAFE:
        return 3;
      case ScanProfile.WEB_STANDARD:
      case ScanProfile.API_STANDARD:
      case ScanProfile.CICD:
        return 6;
      case ScanProfile.SECURITY_LAB:
      case ScanProfile.FULL_ASSESSMENT:
      default:
        return 15;
    }
  }
}
