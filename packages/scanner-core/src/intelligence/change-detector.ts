import type { ISecurityRule } from '@securityscan/contracts';

export interface IntelligenceDiff {
  rules: {
    added: string[];
    modified: string[];
    deprecated: string[];
    removed: string[];
    unchanged: string[];
  };
  payloads: {
    added: string[];
    modified: string[];
    removed: string[];
    unchanged: string[];
  };
  hasBreakingChanges: boolean;
  summary: string;
}

export interface PayloadSummary {
  id: string;
  version: string;
  template?: { raw: string };
  contentHash?: string;
}

export class IntelligenceChangeDetector {
  static diff(
    currentRules: ISecurityRule[],
    incomingRules: ISecurityRule[],
    currentPayloads: PayloadSummary[],
    incomingPayloads: PayloadSummary[],
  ): IntelligenceDiff {
    const currentRuleMap = new Map(currentRules.map((r) => [r.id, r]));
    const incomingRuleMap = new Map(incomingRules.map((r) => [r.id, r]));

    const rulesAdded: string[] = [];
    const rulesModified: string[] = [];
    const rulesDeprecated: string[] = [];
    const rulesRemoved: string[] = [];
    const rulesUnchanged: string[] = [];

    for (const [id, incoming] of incomingRuleMap) {
      const current = currentRuleMap.get(id);
      if (!current) {
        rulesAdded.push(id);
      } else if (incoming.status === 'DEPRECATED' && current.status !== 'DEPRECATED') {
        rulesDeprecated.push(id);
      } else if (incoming.contentHash && current.contentHash && incoming.contentHash !== current.contentHash) {
        rulesModified.push(id);
      } else {
        rulesUnchanged.push(id);
      }
    }

    for (const id of currentRuleMap.keys()) {
      if (!incomingRuleMap.has(id)) {
        rulesRemoved.push(id);
      }
    }

    const currentPayloadMap = new Map(currentPayloads.map((p) => [p.id, p]));
    const incomingPayloadMap = new Map(incomingPayloads.map((p) => [p.id, p]));

    const payloadsAdded: string[] = [];
    const payloadsModified: string[] = [];
    const payloadsRemoved: string[] = [];
    const payloadsUnchanged: string[] = [];

    for (const [id, incoming] of incomingPayloadMap) {
      const current = currentPayloadMap.get(id);
      if (!current) {
        payloadsAdded.push(id);
      } else if (
        incoming.version !== current.version ||
        incoming.template?.raw !== current.template?.raw
      ) {
        payloadsModified.push(id);
      } else {
        payloadsUnchanged.push(id);
      }
    }

    for (const id of currentPayloadMap.keys()) {
      if (!incomingPayloadMap.has(id)) {
        payloadsRemoved.push(id);
      }
    }

    const hasBreakingChanges = rulesRemoved.length > 0 || payloadsRemoved.length > 0;
    const summary = `Rules (+${rulesAdded.length}, ~${rulesModified.length}, -${rulesRemoved.length}, ↓${rulesDeprecated.length}), Payloads (+${payloadsAdded.length}, ~${payloadsModified.length}, -${payloadsRemoved.length})`;

    return {
      rules: {
        added: rulesAdded.sort(),
        modified: rulesModified.sort(),
        deprecated: rulesDeprecated.sort(),
        removed: rulesRemoved.sort(),
        unchanged: rulesUnchanged.sort(),
      },
      payloads: {
        added: payloadsAdded.sort(),
        modified: payloadsModified.sort(),
        removed: payloadsRemoved.sort(),
        unchanged: payloadsUnchanged.sort(),
      },
      hasBreakingChanges,
      summary,
    };
  }
}
