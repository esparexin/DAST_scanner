import type {
  IPayloadDefinition,
  ApplicableParameterType,
  ParameterLocation,
  TargetReflectionContext,
  PayloadSafetyLevel,
} from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

/**
 * Multi-dimensional Context Index for O(1) candidate lookup.
 */
export class PayloadContextIndex {
  private byId = new Map<string, IPayloadDefinition>();
  private byCategory = new Map<DetectionCategory, Set<string>>();
  private byParamType = new Map<ApplicableParameterType, Set<string>>();
  private byLocation = new Map<ParameterLocation, Set<string>>();
  private byContext = new Map<TargetReflectionContext, Set<string>>();
  private bySafetyLevel = new Map<PayloadSafetyLevel, Set<string>>();

  index(payload: IPayloadDefinition): void {
    const id = payload.id;
    this.byId.set(id, payload);

    // Index category
    this.addToSetMap(this.byCategory, payload.category, id);

    // Index parameter types
    for (const type of payload.applicability.parameterTypes) {
      this.addToSetMap(this.byParamType, type, id);
    }

    // Index locations
    for (const loc of payload.applicability.parameterLocations) {
      this.addToSetMap(this.byLocation, loc, id);
    }

    // Index reflection contexts
    for (const ctx of payload.applicability.targetContexts) {
      this.addToSetMap(this.byContext, ctx, id);
    }

    // Index safety level
    this.addToSetMap(this.bySafetyLevel, payload.safetyLevel, id);
  }

  remove(id: string): void {
    const payload = this.byId.get(id);
    if (!payload) return;

    this.byId.delete(id);
    this.removeFromSetMap(this.byCategory, payload.category, id);

    for (const type of payload.applicability.parameterTypes) {
      this.removeFromSetMap(this.byParamType, type, id);
    }
    for (const loc of payload.applicability.parameterLocations) {
      this.removeFromSetMap(this.byLocation, loc, id);
    }
    for (const ctx of payload.applicability.targetContexts) {
      this.removeFromSetMap(this.byContext, ctx, id);
    }
    this.removeFromSetMap(this.bySafetyLevel, payload.safetyLevel, id);
  }

  clear(): void {
    this.byId.clear();
    this.byCategory.clear();
    this.byParamType.clear();
    this.byLocation.clear();
    this.byContext.clear();
    this.bySafetyLevel.clear();
  }

  get(id: string): IPayloadDefinition | undefined {
    return this.byId.get(id);
  }

  getAll(): IPayloadDefinition[] {
    return Array.from(this.byId.values());
  }

  /**
   * Query candidate payload IDs matching all specified filter constraints
   */
  queryCandidateIds(filter: {
    category?: DetectionCategory;
    paramType?: ApplicableParameterType;
    location?: ParameterLocation;
    context?: TargetReflectionContext;
    maxSafetyLevel?: PayloadSafetyLevel;
  }): Set<string> {
    let candidates: Set<string> | null = null;

    const intersect = (set: Set<string> | undefined) => {
      if (!set) return;
      if (candidates === null) {
        candidates = new Set(set);
      } else {
        for (const id of candidates) {
          if (!set.has(id)) candidates.delete(id);
        }
      }
    };

    if (filter.category) {
      intersect(this.byCategory.get(filter.category));
    }
    if (filter.paramType) {
      intersect(this.byParamType.get(filter.paramType));
    }
    if (filter.location) {
      intersect(this.byLocation.get(filter.location));
    }
    if (filter.context && filter.context !== 'ANY') {
      // Union of context-specific and ANY-context payloads
      const specific = this.byContext.get(filter.context) ?? new Set();
      const anyCtx = this.byContext.get('ANY') ?? new Set();
      const union = new Set([...specific, ...anyCtx]);
      intersect(union);
    }

    return candidates ?? new Set(this.byId.keys());
  }

  private addToSetMap<K>(map: Map<K, Set<string>>, key: K, value: string): void {
    let set = map.get(key);
    if (!set) {
      set = new Set();
      map.set(key, set);
    }
    set.add(value);
  }

  private removeFromSetMap<K>(map: Map<K, Set<string>>, key: K, value: string): void {
    const set = map.get(key);
    if (set) {
      set.delete(value);
      if (set.size === 0) map.delete(key);
    }
  }
}
