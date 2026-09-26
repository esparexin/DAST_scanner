import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SubscriptionTier, ScanStatus } from '@securityscan/contracts';
import { ProjectModel, ScanModel, TargetModel } from '@securityscan/database';
import { checkScanQuota, checkTargetQuota } from '../services/quota.service.js';

vi.mock('@securityscan/database', () => ({
  ProjectModel: {
    find: vi.fn(),
  },
  ScanModel: {
    countDocuments: vi.fn(),
  },
  TargetModel: {
    countDocuments: vi.fn(),
  },
}));

describe('Quota Enforcement Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (ProjectModel.find as any).mockReturnValue({
      select: vi.fn().mockResolvedValue([{ _id: 'proj-1' }]),
    });
  });

  describe('checkScanQuota', () => {
    it('rejects profiles not allowed on FREE tier', async () => {
      const result = await checkScanQuota('user-1', SubscriptionTier.FREE, 'FULL_ASSESSMENT');
      expect(result.allowed).toBe(false);
      expect(result.code).toBe('PROFILE_NOT_ALLOWED');
      expect(result.message).toContain('Profile \'FULL_ASSESSMENT\' is not available on the FREE plan');
    });

    it('allows valid profile on FREE tier', async () => {
      (ScanModel.countDocuments as any).mockResolvedValue(0);

      const result = await checkScanQuota('user-1', SubscriptionTier.FREE, 'QUICK');
      expect(result.allowed).toBe(true);
    });

    it('rejects when concurrent scan limit is exceeded on FREE tier (limit 1)', async () => {
      (ScanModel.countDocuments as any).mockResolvedValueOnce(1); // 1 active scan already

      const result = await checkScanQuota('user-1', SubscriptionTier.FREE, 'WEB_STANDARD');
      expect(result.allowed).toBe(false);
      expect(result.code).toBe('QUOTA_EXCEEDED');
      expect(result.message).toContain('Active scan limit reached for FREE plan');
    });

    it('rejects when monthly scan limit is exhausted on FREE tier (limit 10)', async () => {
      (ScanModel.countDocuments as any)
        .mockResolvedValueOnce(0) // 0 active
        .mockResolvedValueOnce(10); // 10 this month

      const result = await checkScanQuota('user-1', SubscriptionTier.FREE, 'WEB_STANDARD');
      expect(result.allowed).toBe(false);
      expect(result.code).toBe('QUOTA_EXCEEDED');
      expect(result.message).toContain('Monthly scan quota exhausted for FREE plan');
    });

    it('allows higher concurrency on TEAM tier', async () => {
      (ScanModel.countDocuments as any)
        .mockResolvedValueOnce(5) // 5 active (< 10)
        .mockResolvedValueOnce(50); // 50 this month (< 500)

      const result = await checkScanQuota('user-1', SubscriptionTier.TEAM, 'FULL_ASSESSMENT');
      expect(result.allowed).toBe(true);
    });
  });

  describe('checkTargetQuota', () => {
    it('allows target creation within tier limit', async () => {
      (TargetModel.countDocuments as any).mockResolvedValue(2); // 2 < 3

      const result = await checkTargetQuota('user-1', SubscriptionTier.FREE);
      expect(result.allowed).toBe(true);
    });

    it('blocks target creation exceeding FREE tier limit of 3', async () => {
      (TargetModel.countDocuments as any).mockResolvedValue(3); // 3 >= 3

      const result = await checkTargetQuota('user-1', SubscriptionTier.FREE);
      expect(result.allowed).toBe(false);
      expect(result.code).toBe('QUOTA_EXCEEDED');
      expect(result.message).toContain('Target quota limit reached for FREE plan (3/3)');
    });

    it('allows up to 100 targets on TEAM tier', async () => {
      (TargetModel.countDocuments as any).mockResolvedValue(50);

      const result = await checkTargetQuota('user-1', SubscriptionTier.TEAM);
      expect(result.allowed).toBe(true);
    });
  });
});
