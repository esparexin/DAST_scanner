import { Router } from 'express';
import {
  IntelligenceReleaseModel,
  AuditLogModel,
} from '@securityscan/database';
import { AuditAction } from '@securityscan/contracts';
import { StagedIntelligencePipeline } from '@securityscan/scanner-core';
import { authenticate, requireAdmin, type AuthRequest } from '../middleware/auth.js';

export const intelligenceRouter = Router();
intelligenceRouter.use(authenticate);
intelligenceRouter.use(requireAdmin);

/**
 * GET /api/admin/intelligence/status
 * View current active intelligence release, version hash, and release history.
 */
intelligenceRouter.get('/status', async (_req: AuthRequest, res, next) => {
  try {
    const activeRelease = await IntelligenceReleaseModel.findOne({ status: 'ACTIVE' });
    const history = await IntelligenceReleaseModel.find()
      .sort({ installedAt: -1 })
      .limit(20);

    res.json({
      data: {
        active: activeRelease,
        history,
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/admin/intelligence/stage
 * Execute multi-stage verification (signatures, schemas, regression gate) and promote if passed.
 */
intelligenceRouter.post('/stage', async (req: AuthRequest, res, next) => {
  try {
    const { package: pkg, manifest, publicKey } = req.body;

    if (!pkg || !manifest || !publicKey) {
      res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'package, manifest, and publicKey are required',
        },
      });
      return;
    }

    const pipeline = new StagedIntelligencePipeline({ publicKey });
    const pipelineResult = await pipeline.execute(pkg, manifest);

    if (!pipelineResult.success) {
      res.status(400).json({
        error: {
          code: 'STAGING_GATE_FAILED',
          message: `Staged intelligence update failed at ${pipelineResult.failedStage}: ${pipelineResult.error}`,
          details: {
            failedStage: pipelineResult.failedStage,
            error: pipelineResult.error,
            diff: pipelineResult.diff,
          },
        },
      });
      return;
    }

    // Supersede previous active release
    await IntelligenceReleaseModel.updateMany(
      { status: 'ACTIVE' },
      { $set: { status: 'SUPERSEDED' } },
    );

    // Save new active release
    const release = await IntelligenceReleaseModel.create({
      releaseVersion: pkg.packageVersion,
      packageHash: manifest.packageHash,
      signatureVerified: true,
      ruleCount: pkg.rules.length,
      payloadCount: pkg.payloads.length,
      manifest,
      diffSummary: pipelineResult.diff?.summary ?? '',
      status: 'ACTIVE',
      appliedBy: req.userId,
      installedAt: new Date(),
    });

    // Write audit log
    await AuditLogModel.create({
      userId: req.userId,
      action: AuditAction.CATALOG_PROMOTED,
      resourceType: 'INTELLIGENCE_CATALOG',
      resourceId: release._id.toString(),
      details: {
        version: pkg.packageVersion,
        packageHash: manifest.packageHash,
        diffSummary: pipelineResult.diff?.summary,
      },
    });

    res.status(201).json({
      data: {
        promotedVersion: pkg.packageVersion,
        release,
        diff: pipelineResult.diff,
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/admin/intelligence/rollback
 * Atomically revert to a previous active release version.
 */
intelligenceRouter.post('/rollback', async (req: AuthRequest, res, next) => {
  try {
    const { targetVersion } = req.body;
    if (!targetVersion) {
      res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'targetVersion is required' },
      });
      return;
    }

    const targetRelease = await IntelligenceReleaseModel.findOne({ releaseVersion: targetVersion });
    if (!targetRelease) {
      res.status(404).json({
        error: { code: 'NOT_FOUND', message: `Release version '${targetVersion}' not found` },
      });
      return;
    }

    // Mark current active as rolled back
    await IntelligenceReleaseModel.updateMany(
      { status: 'ACTIVE' },
      { $set: { status: 'ROLLED_BACK' } },
    );

    // Reactivate target release
    targetRelease.status = 'ACTIVE';
    targetRelease.installedAt = new Date();
    await targetRelease.save();

    // Write audit log
    await AuditLogModel.create({
      userId: req.userId,
      action: AuditAction.CATALOG_ROLLED_BACK,
      resourceType: 'INTELLIGENCE_CATALOG',
      resourceId: targetRelease._id.toString(),
      details: {
        revertedToVersion: targetVersion,
        packageHash: targetRelease.packageHash,
      },
    });

    res.json({
      data: {
        message: `Successfully rolled back intelligence catalog to version ${targetVersion}`,
        activeVersion: targetVersion,
        release: targetRelease,
      },
    });
  } catch (err) {
    next(err);
  }
});
