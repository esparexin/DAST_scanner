import {
  type SecurityIntelligencePackage,
  type SecurityIntelligenceManifest,
  type ISecurityRule,
} from '@securityscan/contracts';
import { CatalogSigner } from '@securityscan/payload-engine';
import { createLogger } from '@securityscan/shared';
import { IntelligenceChangeDetector, type IntelligenceDiff, type PayloadSummary } from './change-detector.js';

const logger = createLogger('staged-intelligence-pipeline');

export type PipelineStage =
  | 'SIGNATURE_VERIFICATION'
  | 'SCHEMA_VALIDATION'
  | 'CHANGE_DETECTION'
  | 'REGRESSION_TESTING'
  | 'PROMOTION';

export interface StagedPipelineOptions {
  publicKey: string;
  regressionTestRunner?: (pkg: SecurityIntelligencePackage) => Promise<{ passed: boolean; failures?: string[] }>;
  currentRules?: ISecurityRule[];
  currentPayloads?: PayloadSummary[];
}

export interface StagedPipelineResult {
  success: boolean;
  promotedVersion?: string;
  failedStage?: PipelineStage;
  error?: string;
  diff?: IntelligenceDiff;
  manifest?: SecurityIntelligenceManifest;
  testedAt: string;
}

export class StagedIntelligencePipeline {
  private readonly options: StagedPipelineOptions;

  constructor(options: StagedPipelineOptions) {
    this.options = options;
  }

  async execute(
    pkg: SecurityIntelligencePackage,
    manifest: SecurityIntelligenceManifest,
  ): Promise<StagedPipelineResult> {
    const testedAt = new Date().toISOString();

    // Stage 1: Cryptographic Signature & Hash Verification
    logger.info({ version: pkg.packageVersion }, 'Stage 1: Verifying digital signature and content hashes');
    const signatureValid = CatalogSigner.verifyPackage(manifest, pkg, this.options.publicKey);
    if (!signatureValid) {
      logger.error({ version: pkg.packageVersion }, 'Package failed cryptographic signature verification');
      return {
        success: false,
        failedStage: 'SIGNATURE_VERIFICATION',
        error: 'Cryptographic signature or content hash mismatch',
        testedAt,
      };
    }

    // Stage 2: Schema & Integrity Validation
    logger.info({ version: pkg.packageVersion }, 'Stage 2: Validating schema structures and rule definitions');
    for (const rule of pkg.rules) {
      if (!rule.id || !rule.name || !rule.category || !rule.type || !rule.severity || !rule.confidence) {
        return {
          success: false,
          failedStage: 'SCHEMA_VALIDATION',
          error: `Rule ${rule.id ?? 'UNKNOWN'} failed schema validation: required fields missing`,
          testedAt,
        };
      }
    }

    for (const payload of pkg.payloads) {
      if (!payload.id || !payload.version || !payload.template?.raw) {
        return {
          success: false,
          failedStage: 'SCHEMA_VALIDATION',
          error: `Payload ${payload.id ?? 'UNKNOWN'} failed schema validation: missing template`,
          testedAt,
        };
      }
    }

    // Stage 3: Change Detection
    logger.info({ version: pkg.packageVersion }, 'Stage 3: Computing intelligence delta and change metrics');
    const diff = IntelligenceChangeDetector.diff(
      this.options.currentRules ?? [],
      pkg.rules,
      this.options.currentPayloads ?? [],
      pkg.payloads as PayloadSummary[],
    );
    logger.info({ summary: diff.summary }, 'Change detection completed');

    // Stage 4: Automated In-Memory Security Lab Regression Gate
    logger.info({ version: pkg.packageVersion }, 'Stage 4: Running automated security regression test gate');
    if (this.options.regressionTestRunner) {
      try {
        const testResult = await this.options.regressionTestRunner(pkg);
        if (!testResult.passed) {
          logger.error({ failures: testResult.failures }, 'Security regression tests failed');
          return {
            success: false,
            failedStage: 'REGRESSION_TESTING',
            error: `Regression tests failed: ${testResult.failures?.join(', ') ?? 'Unknown failure'}`,
            diff,
            testedAt,
          };
        }
      } catch (err: any) {
        return {
          success: false,
          failedStage: 'REGRESSION_TESTING',
          error: `Regression runner threw exception: ${err?.message ?? 'Execution error'}`,
          diff,
          testedAt,
        };
      }
    } else {
      // Default built-in smoke sanity check
      if (pkg.rules.length === 0 && pkg.payloads.length === 0) {
        return {
          success: false,
          failedStage: 'REGRESSION_TESTING',
          error: 'Package contains zero rules and zero payloads (empty package rejected)',
          diff,
          testedAt,
        };
      }
    }

    // Stage 5: Promotion Gate Passed
    logger.info(
      { version: pkg.packageVersion, summary: diff.summary },
      'Stage 5: Security intelligence package passed all staging gates and is ready for promotion',
    );

    return {
      success: true,
      promotedVersion: pkg.packageVersion,
      diff,
      manifest,
      testedAt,
    };
  }
}
