import { Router } from 'express';
import {
  ScanScheduleModel,
  TargetModel,
  ProjectModel,
} from '@securityscan/database';
import {
  OrgRole,
  AuthorizationState,
  ScanProfile,
  SubscriptionTier,
} from '@securityscan/contracts';
import { checkScanQuota } from '../services/quota.service.js';
import { authenticate } from '../middleware/auth.js';
import { resolveTenant, requireOrgRole, type TenantRequest } from '../middleware/tenant.js';
import { resolveCronPattern, executeScheduledScan } from '../services/schedule.service.js';

export const scheduleRouter = Router();
scheduleRouter.use(authenticate);
scheduleRouter.use(resolveTenant);

// List schedules for organization
scheduleRouter.get('/', async (req: TenantRequest, res, next) => {
  try {
    const filter: Record<string, unknown> = {
      organizationId: req.organizationId,
    };
    if (req.query['projectId']) filter['projectId'] = req.query['projectId'];
    if (req.query['targetId']) filter['targetId'] = req.query['targetId'];

    const schedules = await ScanScheduleModel.find(filter).sort({ createdAt: -1 });
    res.json({ data: schedules });
  } catch (err) {
    next(err);
  }
});

// Get single schedule
scheduleRouter.get('/:id', async (req: TenantRequest, res, next) => {
  try {
    const schedule = await ScanScheduleModel.findOne({
      _id: req.params['id'],
      organizationId: req.organizationId,
    });
    if (!schedule) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan schedule not found' } });
      return;
    }
    res.json({ data: schedule });
  } catch (err) {
    next(err);
  }
});

// Create new schedule (restricted to ORG_ADMIN and SECURITY_LEAD)
scheduleRouter.post(
  '/',
  requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]),
  async (req: TenantRequest, res, next) => {
    try {
      const { name, projectId, targetId, frequency, cron, profile, enabled } = req.body;

      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Schedule name is required' } });
        return;
      }

      if (!projectId || !targetId) {
        res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'projectId and targetId are required' } });
        return;
      }

      // Verify project exists and user has access
      const project = await ProjectModel.findOne({ _id: projectId });
      if (!project) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
        return;
      }

      // Verify target exists and is authorized
      const target = await TargetModel.findOne({ _id: targetId, projectId });
      if (!target) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found in project' } });
        return;
      }

      if (target.authorization !== AuthorizationState.AUTHORIZED) {
        res.status(400).json({
          error: {
            code: 'TARGET_NOT_AUTHORIZED',
            message: 'Target domain must be verified and AUTHORIZED before scheduling recurring scans',
          },
        });
        return;
      }

      // Resolve cron pattern
      let patternResult;
      try {
        patternResult = resolveCronPattern(frequency, cron);
      } catch (cronErr: any) {
        res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: cronErr.message } });
        return;
      }

      // Validate tier profile permission via quota service (SSOT)
      const selectedProfile = profile ?? ScanProfile.WEB_STANDARD;
      const tier = req.orgTier ?? SubscriptionTier.FREE;
      const profileCheck = await checkScanQuota(req.userId!, tier, selectedProfile);
      if (!profileCheck.allowed && profileCheck.code === 'PROFILE_NOT_ALLOWED') {
        res.status(403).json({ error: { code: profileCheck.code, message: profileCheck.message } });
        return;
      }

      const schedule = await ScanScheduleModel.create({
        organizationId: req.organizationId,
        projectId,
        targetId,
        name: name.trim(),
        cron: patternResult.cron,
        frequency: patternResult.frequency,
        profile: selectedProfile,
        enabled: enabled ?? true,
      });

      res.status(201).json({ data: schedule });
    } catch (err) {
      next(err);
    }
  },
);

// Update schedule
scheduleRouter.patch(
  '/:id',
  requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]),
  async (req: TenantRequest, res, next) => {
    try {
      const schedule = await ScanScheduleModel.findOne({
        _id: req.params['id'],
        organizationId: req.organizationId,
      });
      if (!schedule) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan schedule not found' } });
        return;
      }

      const { name, frequency, cron, profile, enabled } = req.body;
      const updates: Record<string, unknown> = {};

      if (name && typeof name === 'string') updates['name'] = name.trim();
      if (typeof enabled === 'boolean') updates['enabled'] = enabled;

      if (frequency || cron) {
        try {
          const resolved = resolveCronPattern(frequency ?? schedule.frequency, cron);
          updates['cron'] = resolved.cron;
          updates['frequency'] = resolved.frequency;
        } catch (cronErr: any) {
          res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: cronErr.message } });
          return;
        }
      }

      if (profile) {
        const tier = req.orgTier ?? SubscriptionTier.FREE;
        const profileCheck = await checkScanQuota(req.userId!, tier, profile);
        if (!profileCheck.allowed && profileCheck.code === 'PROFILE_NOT_ALLOWED') {
          res.status(403).json({ error: { code: profileCheck.code, message: profileCheck.message } });
          return;
        }
        updates['profile'] = profile;
      }

      const updated = await ScanScheduleModel.findByIdAndUpdate(schedule._id, updates, { new: true });
      res.json({ data: updated });
    } catch (err) {
      next(err);
    }
  },
);

// Delete schedule
scheduleRouter.delete(
  '/:id',
  requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]),
  async (req: TenantRequest, res, next) => {
    try {
      const deleted = await ScanScheduleModel.findOneAndDelete({
        _id: req.params['id'],
        organizationId: req.organizationId,
      });
      if (!deleted) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan schedule not found' } });
        return;
      }
      res.json({ data: { message: 'Scan schedule deleted successfully' } });
    } catch (err) {
      next(err);
    }
  },
);

// Manually trigger immediate execution of scheduled scan
scheduleRouter.post(
  '/:id/run',
  requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]),
  async (req: TenantRequest, res, next) => {
    try {
      const schedule = await ScanScheduleModel.findOne({
        _id: req.params['id'],
        organizationId: req.organizationId,
      });
      if (!schedule) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Scan schedule not found' } });
        return;
      }

      const result = await executeScheduledScan(
        schedule._id.toString(),
        req.userId!,
        req.orgTier ?? SubscriptionTier.FREE,
      );

      if (!result.success) {
        res.status(400).json({ error: { code: result.code ?? 'EXECUTION_FAILED', message: result.error } });
        return;
      }

      res.status(202).json({
        data: {
          message: 'Scheduled scan triggered successfully',
          scanId: result.scanId,
          scheduleId: schedule._id.toString(),
        },
      });
    } catch (err) {
      next(err);
    }
  },
);
