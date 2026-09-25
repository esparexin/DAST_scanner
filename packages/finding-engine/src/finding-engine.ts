import { createHash } from 'node:crypto';
import { FindingStatus } from '@securityscan/contracts';
import type { ICreateFinding } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('finding-engine');

export interface NormalizedFinding extends ICreateFinding {
  deduplicationKey: string;
  status: FindingStatus;
}

export class FindingEngine {
  private seen: Set<string> = new Set();

  /**
   * Normalize a raw detection result into a finding with deduplication key.
   * Returns null if this is a duplicate within the current scan.
   */
  normalize(finding: ICreateFinding): NormalizedFinding | null {
    const dedupKey = this.computeDeduplicationKey(finding);

    if (this.seen.has(dedupKey)) {
      logger.debug({ ruleId: finding.ruleId, endpoint: finding.endpoint }, 'Duplicate finding skipped');
      return null;
    }

    this.seen.add(dedupKey);

    return {
      ...finding,
      deduplicationKey: dedupKey,
      status: FindingStatus.CANDIDATE,
    };
  }

  /**
   * Create a stable deduplication key from finding attributes.
   * Same rule + endpoint + parameter + method = same finding.
   */
  private computeDeduplicationKey(finding: ICreateFinding): string {
    const input = [
      finding.ruleId,
      finding.endpoint,
      finding.method,
      finding.parameter ?? '',
      finding.targetId,
    ].join('::');
    return createHash('sha256').update(input).digest('hex').slice(0, 32);
  }

  reset(): void {
    this.seen.clear();
  }
}
