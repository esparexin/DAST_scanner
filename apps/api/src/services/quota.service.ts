import {
  SubscriptionTier,
  SUBSCRIPTION_TIER_QUOTAS,
  ScanStatus,
} from '@securityscan/contracts';
import { ScanModel, TargetModel, ProjectModel } from '@securityscan/database';

export interface QuotaCheckResult {
  allowed: boolean;
  code?: 'QUOTA_EXCEEDED' | 'PROFILE_NOT_ALLOWED' | 'DURATION_EXCEEDED';
  message?: string;
  details?: Record<string, unknown>;
}

export async function checkScanQuota(
  userId: string,
  tier: SubscriptionTier,
  profile: string,
): Promise<QuotaCheckResult> {
  const quotas = SUBSCRIPTION_TIER_QUOTAS[tier] ?? SUBSCRIPTION_TIER_QUOTAS[SubscriptionTier.FREE];

  // 1. Profile restriction
  if (quotas?.allowedProfiles && !quotas.allowedProfiles.includes(profile)) {
    return {
      allowed: false,
      code: 'PROFILE_NOT_ALLOWED',
      message: `Profile '${profile}' is not available on the ${tier} plan. Allowed profiles: ${quotas.allowedProfiles.join(', ')}`,
    };
  }

  // Find user projects
  const userProjects = await ProjectModel.find({ ownerId: userId }).select('_id');
  const projectIds = userProjects.map((p) => p._id);

  // 2. Active concurrent scans limit
  const activeStatuses = [
    ScanStatus.QUEUED,
    ScanStatus.DISCOVERING,
    ScanStatus.CRAWLING,
    ScanStatus.PASSIVE_ANALYSIS,
    ScanStatus.ACTIVE_TESTING,
    ScanStatus.API_TESTING,
    ScanStatus.VERIFYING,
    ScanStatus.EVIDENCE_COLLECTION,
    ScanStatus.REPORTING,
  ];

  const activeCount = await ScanModel.countDocuments({
    projectId: { $in: projectIds },
    status: { $in: activeStatuses },
  });

  if (quotas && activeCount >= quotas.maxConcurrentScans) {
    return {
      allowed: false,
      code: 'QUOTA_EXCEEDED',
      message: `Active scan limit reached for ${tier} plan (${activeCount}/${quotas.maxConcurrentScans}). Please wait for active scans to complete or upgrade your plan.`,
      details: { activeCount, maxConcurrent: quotas.maxConcurrentScans },
    };
  }

  // 3. Monthly scan quota
  const startOfMonth = new Date();
  startOfMonth.setDate(1);
  startOfMonth.setHours(0, 0, 0, 0);

  const monthlyCount = await ScanModel.countDocuments({
    projectId: { $in: projectIds },
    createdAt: { $gte: startOfMonth },
  });

  if (quotas && monthlyCount >= quotas.maxScansPerMonth) {
    return {
      allowed: false,
      code: 'QUOTA_EXCEEDED',
      message: `Monthly scan quota exhausted for ${tier} plan (${monthlyCount}/${quotas.maxScansPerMonth}). Upgrade your plan to run additional scans this month.`,
      details: { monthlyCount, maxMonthly: quotas.maxScansPerMonth },
    };
  }

  return { allowed: true };
}

export async function checkTargetQuota(
  userId: string,
  tier: SubscriptionTier,
): Promise<QuotaCheckResult> {
  const quotas = SUBSCRIPTION_TIER_QUOTAS[tier] ?? SUBSCRIPTION_TIER_QUOTAS[SubscriptionTier.FREE];
  const userProjects = await ProjectModel.find({ ownerId: userId }).select('_id');
  const projectIds = userProjects.map((p) => p._id);

  const targetCount = await TargetModel.countDocuments({
    projectId: { $in: projectIds },
  });

  if (quotas && targetCount >= quotas.maxAuthorizedTargets) {
    return {
      allowed: false,
      code: 'QUOTA_EXCEEDED',
      message: `Target quota limit reached for ${tier} plan (${targetCount}/${quotas.maxAuthorizedTargets}). Upgrade your plan to add more targets.`,
      details: { targetCount, maxTargets: quotas.maxAuthorizedTargets },
    };
  }

  return { allowed: true };
}
