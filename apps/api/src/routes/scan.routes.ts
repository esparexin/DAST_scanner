import { Router } from 'express';
import { ScanModel, TargetModel, ProjectModel } from '@securityscan/database';
import {
  CreateScanSchema,
  ScanStatus,
  AuthorizationState,
  SCAN_STATE_TRANSITIONS,
} from '@securityscan/contracts';
import { ScopeGuard } from '@securityscan/scope';
import { SCAN_EVENTS_CHANNEL, createRedisClient } from '@securityscan/scanner-core';
import { authenticate, type AuthRequest } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { enqueueScan } from '../services/queue.service.js';

export const scanRouter = Router();
scanRouter.use(authenticate);

scanRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.query;
    const filter: Record<string, unknown> = {};
    if (projectId) {
      const project = await ProjectModel.findOne({ _id: projectId, ownerId: req.userId });
      if (!project) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
        return;
      }
      filter['projectId'] = projectId;
    }
    const scans = await ScanModel.find(filter).sort({ createdAt: -1 }).limit(50);
    res.json({ data: scans });
  } catch (err) {
    next(err);
  }
});

scanRouter.get('/:id', async (req: AuthRequest, res, next) => {
  try {
    const scan = await ScanModel.findById(req.params['id']);
    if (!scan) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan not found' } });
      return;
    }
    res.json({ data: scan });
  } catch (err) {
    next(err);
  }
});

scanRouter.post('/', validate(CreateScanSchema), async (req: AuthRequest, res, next) => {
  try {
    const { projectId, targetId, profile, dryRun, authProfileIds, enabledCategories, excludedChecks } = req.body;

    // Verify ownership
    const project = await ProjectModel.findOne({ _id: projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }

    const target = await TargetModel.findOne({ _id: targetId, projectId });
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }

    // ENFORCE: NO AUTHORIZATION = NO SCAN
    if (target.authorization !== AuthorizationState.AUTHORIZED) {
      res.status(403).json({
        error: {
          code: 'SCOPE_VIOLATION',
          message: 'Target is not authorized. Set authorization to AUTHORIZED before scanning.',
        },
      });
      return;
    }

    // Validate scope before creating scan
    const scopeErrors = ScopeGuard.validate({
      scanId: 'pre-validation',
      targetId: targetId,
      projectId: projectId,
      authorized: true,
      allowedHosts: target.scope.allowedHosts,
      excludedHosts: target.scope.excludedHosts,
      allowedPaths: target.scope.allowedPaths,
      excludedPaths: target.scope.excludedPaths,
      maxRequestsPerSecond: target.scope.maxRequestsPerSecond,
      maxConcurrency: target.scope.maxConcurrency,
      maxRequests: target.scope.maxRequests,
      maxCrawlDepth: target.scope.maxCrawlDepth,
      maxResponseSize: target.scope.maxResponseSize,
      maxScanDuration: target.scope.maxScanDuration,
      timeoutPerRequest: target.scope.timeoutPerRequest,
    });

    // Allow the pre-validation scanId
    const realErrors = scopeErrors.filter((e) => !e.includes('Scan ID'));
    if (realErrors.length > 0) {
      res.status(400).json({
        error: { code: 'SCOPE_VIOLATION', message: 'Scope validation failed', details: realErrors },
      });
      return;
    }

    const scan = await ScanModel.create({
      projectId,
      targetId,
      profile,
      dryRun: dryRun ?? false,
      status: ScanStatus.CREATED,
      configuration: {
        profile,
        authProfileIds: authProfileIds ?? [],
        enabledCategories: enabledCategories ?? [],
        excludedChecks: excludedChecks ?? [],
        maxRequestsPerSecond: target.scope.maxRequestsPerSecond,
        maxConcurrency: target.scope.maxConcurrency,
        maxRequests: target.scope.maxRequests,
        maxCrawlDepth: target.scope.maxCrawlDepth,
        maxResponseSize: target.scope.maxResponseSize,
        maxScanDuration: target.scope.maxScanDuration,
        timeoutPerRequest: target.scope.timeoutPerRequest,
        followRedirects: true,
        maxRedirects: 10,
      },
    });

    // Enqueue for processing
    await enqueueScan(scan._id.toString());

    res.status(201).json({ data: scan });
  } catch (err) {
    next(err);
  }
});

scanRouter.post('/:id/cancel', async (req: AuthRequest, res, next) => {
  try {
    const scan = await ScanModel.findById(req.params['id']);
    if (!scan) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan not found' } });
      return;
    }

    const allowed = SCAN_STATE_TRANSITIONS[scan.status as ScanStatus];
    if (!allowed?.includes(ScanStatus.CANCELLED)) {
      res.status(400).json({
        error: { code: 'INVALID_STATE', message: `Cannot cancel scan in state ${scan.status}` },
      });
      return;
    }

    scan.status = ScanStatus.CANCELLED;
    scan.cancelledAt = new Date();
    await scan.save();

    res.json({ data: scan });
  } catch (err) {
    next(err);
  }
});

// Dry-run endpoint
scanRouter.post('/:id/dry-run', async (req: AuthRequest, res, next) => {
  try {
    const scan = await ScanModel.findById(req.params['id']);
    if (!scan) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan not found' } });
      return;
    }
    const target = await TargetModel.findById(scan.targetId);
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }

    res.json({
      data: {
        target: target.baseUrl,
        allowedHosts: target.scope.allowedHosts,
        excludedHosts: target.scope.excludedHosts,
        allowedPaths: target.scope.allowedPaths,
        excludedPaths: target.scope.excludedPaths,
        scanProfile: scan.profile,
        authProfileCount: scan.configuration.authProfileIds.length,
        enabledCategories: scan.configuration.enabledCategories,
        maxRequestsPerSecond: scan.configuration.maxRequestsPerSecond,
        maxConcurrency: scan.configuration.maxConcurrency,
        maxRequests: scan.configuration.maxRequests,
        maxCrawlDepth: scan.configuration.maxCrawlDepth,
        maxScanDuration: scan.configuration.maxScanDuration,
        dryRun: scan.dryRun,
      },
    });
  } catch (err) {
    next(err);
  }
});

// SSE endpoint for live scan progress streaming
scanRouter.get('/:id/events', async (req: AuthRequest, res, next) => {
  try {
    const scan = await ScanModel.findById(req.params['id']);
    if (!scan) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan not found' } });
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });

    // Send initial snapshot
    res.write(
      `data: ${JSON.stringify({
        scanId: scan._id.toString(),
        phase: scan.status,
        timestamp: new Date().toISOString(),
        progress: scan.progress,
      })}\n\n`,
    );

    if (
      scan.status === ScanStatus.COMPLETED ||
      scan.status === ScanStatus.FAILED ||
      scan.status === ScanStatus.CANCELLED
    ) {
      res.end();
      return;
    }

    const subscriber = createRedisClient();
    await subscriber.connect().catch(() => {});

    const onMessage = (_channel: string, message: string) => {
      try {
        const event = JSON.parse(message);
        if (event.scanId === scan._id.toString()) {
          res.write(`data: ${message}\n\n`);
          if (
            event.phase === ScanStatus.COMPLETED ||
            event.phase === ScanStatus.FAILED ||
            event.phase === ScanStatus.CANCELLED
          ) {
            cleanup();
            res.end();
          }
        }
      } catch {
        // ignore parse errors
      }
    };

    const cleanup = () => {
      subscriber.off('message', onMessage);
      subscriber.unsubscribe(SCAN_EVENTS_CHANNEL).catch(() => {});
      subscriber.quit().catch(() => {});
    };

    subscriber.on('message', onMessage);
    await subscriber.subscribe(SCAN_EVENTS_CHANNEL);

    req.on('close', cleanup);
  } catch (err) {
    next(err);
  }
});

