import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  ScheduleFrequency,
  SCHEDULE_CRON_PATTERNS,
  ScanProfile,
  ScanStatus,
  AuthorizationState,
  SubscriptionTier,
  OrgRole,
} from '@securityscan/contracts';
import {
  ScanScheduleModel,
  TargetModel,
  ProjectModel,
  ScanModel,
} from '@securityscan/database';
import {
  validateCronExpression,
  resolveCronPattern,
  executeScheduledScan,
} from '../services/schedule.service.js';
import { requireOrgRole, type TenantRequest } from '../middleware/tenant.js';

vi.mock('@securityscan/database', () => ({
  ScanScheduleModel: {
    find: vi.fn(),
    findOne: vi.fn(),
    findById: vi.fn(),
    create: vi.fn(),
    findByIdAndUpdate: vi.fn(),
    findOneAndDelete: vi.fn(),
  },
  TargetModel: {
    find: vi.fn(),
    findOne: vi.fn(),
    findById: vi.fn(),
  },
  ProjectModel: {
    find: vi.fn(),
    findOne: vi.fn(),
  },
  ScanModel: {
    find: vi.fn(),
    findById: vi.fn(),
    create: vi.fn(),
    countDocuments: vi.fn(),
  },
}));

vi.mock('@securityscan/scanner-core', () => ({
  createScanQueue: vi.fn().mockReturnValue({
    add: vi.fn().mockResolvedValue({ id: 'job-sched-1' }),
  }),
}));

describe('Scheduled & Recurring Scans Automation System', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('1. Cron Expression Syntax & Validation', () => {
    it('accepts valid 5-part cron patterns', () => {
      expect(validateCronExpression('0 0 * * *')).toBe(true); // Daily midnight
      expect(validateCronExpression('0 2 * * 0')).toBe(true); // Weekly Sunday 2 AM
      expect(validateCronExpression('0 0 1 * *')).toBe(true); // Monthly 1st day
      expect(validateCronExpression('*/15 * * * *')).toBe(true); // Every 15 mins
      expect(validateCronExpression('0 12 1-15 * 1-5')).toBe(true); // Weekday range
    });

    it('rejects invalid, truncated, or out-of-range cron patterns', () => {
      expect(validateCronExpression('')).toBe(false);
      expect(validateCronExpression('* * *')).toBe(false); // Only 3 parts
      expect(validateCronExpression('* * * * * *')).toBe(false); // 6 parts (second precision not supported)
      expect(validateCronExpression('99 * * * *')).toBe(false); // Minute out of range (0-59)
      expect(validateCronExpression('* 45 * * *')).toBe(false); // Hour out of range (0-23)
      expect(validateCronExpression('invalid cron text')).toBe(false);
    });

    it('resolves standard frequency enums into normalized cron patterns', () => {
      const daily = resolveCronPattern(ScheduleFrequency.DAILY);
      expect(daily.cron).toBe(SCHEDULE_CRON_PATTERNS[ScheduleFrequency.DAILY]);
      expect(daily.frequency).toBe(ScheduleFrequency.DAILY);

      const weekly = resolveCronPattern(ScheduleFrequency.WEEKLY);
      expect(weekly.cron).toBe(SCHEDULE_CRON_PATTERNS[ScheduleFrequency.WEEKLY]);

      const monthly = resolveCronPattern(ScheduleFrequency.MONTHLY);
      expect(monthly.cron).toBe(SCHEDULE_CRON_PATTERNS[ScheduleFrequency.MONTHLY]);
    });

    it('accepts custom valid cron expression', () => {
      const custom = resolveCronPattern(undefined, '30 3 * * 2');
      expect(custom.cron).toBe('30 3 * * 2');
      expect(custom.frequency).toBe(ScheduleFrequency.CUSTOM);
    });

    it('throws error for invalid custom cron pattern', () => {
      expect(() => resolveCronPattern(undefined, 'bad-cron-spec')).toThrow(
        /Invalid custom cron expression/,
      );
    });
  });

  describe('2. Target Verification & Ownership Gates for Scheduled Scans', () => {
    it('aborts scheduled scan execution if target is not AUTHORIZED', async () => {
      (ScanScheduleModel.findById as any).mockResolvedValue({
        _id: 'sched-1',
        organizationId: 'org-1',
        projectId: 'proj-1',
        targetId: 'target-pending-1',
        profile: ScanProfile.WEB_STANDARD,
        enabled: true,
      });

      (TargetModel.findById as any).mockResolvedValue({
        _id: 'target-pending-1',
        authorization: AuthorizationState.PENDING,
      });

      const result = await executeScheduledScan('sched-1', 'user-1', SubscriptionTier.TEAM);

      expect(result.success).toBe(false);
      expect(result.code).toBe('TARGET_NOT_AUTHORIZED');
      expect(result.error).toContain('Target domain is not verified');
      expect(ScanModel.create).not.toHaveBeenCalled();
    });

    it('aborts scheduled scan execution if schedule is disabled', async () => {
      (ScanScheduleModel.findById as any).mockResolvedValue({
        _id: 'sched-disabled',
        enabled: false,
      });

      const result = await executeScheduledScan('sched-disabled', 'user-1', SubscriptionTier.TEAM);

      expect(result.success).toBe(false);
      expect(result.code).toBe('SCHEDULE_DISABLED');
      expect(ScanModel.create).not.toHaveBeenCalled();
    });
  });

  describe('3. Multi-Tenant Quota & Concurrency Enforcement on Scheduled Scans', () => {
    it('blocks execution when plan quota or profile restriction is violated', async () => {
      (ScanScheduleModel.findById as any).mockResolvedValue({
        _id: 'sched-quota-fail',
        organizationId: 'org-free',
        projectId: 'proj-1',
        targetId: 'target-1',
        profile: ScanProfile.FULL_ASSESSMENT, // Not allowed on FREE plan
        enabled: true,
      });

      (TargetModel.findById as any).mockResolvedValue({
        _id: 'target-1',
        authorization: AuthorizationState.AUTHORIZED,
      });

      const result = await executeScheduledScan('sched-quota-fail', 'user-free', SubscriptionTier.FREE);

      expect(result.success).toBe(false);
      expect(result.code).toBe('PROFILE_NOT_ALLOWED');
      expect(result.error).toContain('not available on the FREE plan');
      expect(ScanModel.create).not.toHaveBeenCalled();
    });

    it('successfully triggers scan and dispatches to queue when authorized and quota allows', async () => {
      (ScanScheduleModel.findById as any).mockResolvedValue({
        _id: 'sched-success-1',
        organizationId: 'org-enterprise',
        projectId: 'proj-1',
        targetId: 'target-auth-1',
        profile: ScanProfile.FULL_ASSESSMENT,
        enabled: true,
      });

      (TargetModel.findById as any).mockResolvedValue({
        _id: 'target-auth-1',
        authorization: AuthorizationState.AUTHORIZED,
      });

      (ProjectModel.find as any).mockReturnValue({
        select: vi.fn().mockResolvedValue([{ _id: 'proj-1' }]),
      });
      (ScanModel.countDocuments as any).mockResolvedValue(0);

      (ScanModel.create as any).mockResolvedValue({
        _id: 'scan-scheduled-new-1',
        status: ScanStatus.QUEUED,
      });

      const result = await executeScheduledScan('sched-success-1', 'user-ent', SubscriptionTier.ENTERPRISE);

      expect(result.success).toBe(true);
      expect(result.scanId).toBe('scan-scheduled-new-1');
      expect(ScanModel.create).toHaveBeenCalledWith(
        expect.objectContaining({
          projectId: 'proj-1',
          targetId: 'target-auth-1',
          profile: ScanProfile.FULL_ASSESSMENT,
          status: ScanStatus.QUEUED,
        }),
      );
      expect(ScanScheduleModel.findByIdAndUpdate).toHaveBeenCalledWith(
        'sched-success-1',
        expect.objectContaining({ lastRunAt: expect.any(Date) }),
      );
    });
  });

  describe('4. RBAC Authorization & Permission Gatekeeper', () => {
    it('blocks VIEWER role from creating or modifying scan schedules', () => {
      const rbacGate = requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]);
      const req: Partial<TenantRequest> = {
        orgRole: OrgRole.VIEWER,
      };
      const res: any = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      rbacGate(req as any, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({ code: 'FORBIDDEN' }),
        }),
      );
    });

    it('allows ORG_ADMIN and SECURITY_LEAD to pass schedule management gate', () => {
      const rbacGate = requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]);
      const res: any = { status: vi.fn().mockReturnThis(), json: vi.fn() };

      const nextAdmin = vi.fn();
      rbacGate({ orgRole: OrgRole.ORG_ADMIN } as any, res, nextAdmin);
      expect(nextAdmin).toHaveBeenCalledTimes(1);

      const nextLead = vi.fn();
      rbacGate({ orgRole: OrgRole.SECURITY_LEAD } as any, res, nextLead);
      expect(nextLead).toHaveBeenCalledTimes(1);
    });
  });
});
