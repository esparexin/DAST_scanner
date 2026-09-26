import {
  ScheduleFrequency,
  SCHEDULE_CRON_PATTERNS,
  ScanStatus,
  AuthorizationState,
  SubscriptionTier,
} from '@securityscan/contracts';
import {
  ScanScheduleModel,
  TargetModel,
  ScanModel,
} from '@securityscan/database';
import { checkScanQuota } from './quota.service.js';
import { enqueueScan } from './queue.service.js';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('schedule-service');

/**
 * Validates a standard 5-part cron expression (minute hour day-of-month month day-of-week)
 */
export function validateCronExpression(cron: string): boolean {
  if (!cron || typeof cron !== 'string') return false;
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) return false;

  const patterns = [
    /^(\*|([0-5]?\d)(-[0-5]?\d)?)(\/[1-5]?\d)?(,(\*|([0-5]?\d)(-[0-5]?\d)?)(\/[1-5]?\d)?)*$/, // 0-59 min
    /^(\*|([01]?\d|2[0-3])(-([01]?\d|2[0-3]))?)(\/([01]?\d|2[0-3]))?(,(\*|([01]?\d|2[0-3])(-([01]?\d|2[0-3]))?)(\/([01]?\d|2[0-3]))?)*$/, // 0-23 hr
    /^(\*|([1-9]|[12]\d|3[01])(-([1-9]|[12]\d|3[01]))?)(\/([1-9]|[12]\d|3[01]))?(,(\*|([1-9]|[12]\d|3[01])(-([1-9]|[12]\d|3[01]))?)(\/([1-9]|[12]\d|3[01]))?)*$/, // 1-31 dom
    /^(\*|([1-9]|1[0-2])(-([1-9]|1[0-2]))?)(\/([1-9]|1[0-2]))?(,(\*|([1-9]|1[0-2])(-([1-9]|1[0-2]))?)(\/([1-9]|1[0-2]))?)*$/, // 1-12 month
    /^(\*|[0-6](-[0-6])?)(\/[0-6])?(,(\*|[0-6](-[0-6])?)(\/[0-6])?)*$/, // 0-6 dow
  ];

  return parts.every((part, i) => patterns[i]!.test(part));
}

/**
 * Resolves frequency enum and custom cron string into a normalized cron pattern
 */
export function resolveCronPattern(
  frequency?: ScheduleFrequency,
  customCron?: string,
): { cron: string; frequency: ScheduleFrequency } {
  if (customCron) {
    if (!validateCronExpression(customCron)) {
      throw new Error(`Invalid custom cron expression: '${customCron}'`);
    }
    return { cron: customCron.trim(), frequency: ScheduleFrequency.CUSTOM };
  }

  const selectedFrequency = frequency ?? ScheduleFrequency.DAILY;
  if (selectedFrequency === ScheduleFrequency.CUSTOM) {
    throw new Error('Custom frequency requires a valid custom cron pattern');
  }

  const cron = SCHEDULE_CRON_PATTERNS[selectedFrequency];
  return { cron, frequency: selectedFrequency };
}

/**
 * Executes a scan run triggered from a schedule, validating quotas and domain authorization
 */
export async function executeScheduledScan(
  scheduleId: string,
  actorUserId: string,
  tier: SubscriptionTier,
): Promise<{ success: boolean; scanId?: string; error?: string; code?: string }> {
  try {
    const schedule = await ScanScheduleModel.findById(scheduleId);
    if (!schedule || !schedule.enabled) {
      return { success: false, error: 'Schedule is disabled or not found', code: 'SCHEDULE_DISABLED' };
    }

    // Verify target authorization state
    const target = await TargetModel.findById(schedule.targetId);
    if (!target || target.authorization !== AuthorizationState.AUTHORIZED) {
      logger.warn({ scheduleId, targetId: schedule.targetId }, 'Scheduled scan skipped: target is not AUTHORIZED');
      return {
        success: false,
        error: 'Target domain is not verified or authorization has been revoked',
        code: 'TARGET_NOT_AUTHORIZED',
      };
    }

    // Verify tenant quota allowances
    const quota = await checkScanQuota(actorUserId, tier, schedule.profile);
    if (!quota.allowed) {
      logger.warn({ scheduleId, tier, code: quota.code }, 'Scheduled scan skipped: quota limit reached');
      return {
        success: false,
        error: quota.message ?? 'Quota limit reached for subscription tier',
        code: quota.code ?? 'QUOTA_EXCEEDED',
      };
    }

    // Create the scan record
    const scan = await ScanModel.create({
      projectId: schedule.projectId,
      targetId: schedule.targetId,
      profile: schedule.profile,
      status: ScanStatus.QUEUED,
      progress: {
        phase: ScanStatus.QUEUED,
        totalRequests: 0,
        completedRequests: 0,
        endpointsDiscovered: 0,
        assetsDiscovered: 0,
        checksExecuted: 0,
        checksTotal: 0,
        findingsTotal: 0,
        findingsConfirmed: 0,
        errors: 0,
      },
      configuration: {
        profile: schedule.profile,
        authProfileIds: [],
        enabledCategories: [],
        excludedChecks: [],
        maxRequestsPerSecond: 10,
        maxConcurrency: 5,
        maxRequests: 5000,
        maxCrawlDepth: 5,
        maxResponseSize: 10485760,
        maxScanDuration: 3600,
        timeoutPerRequest: 10000,
        followRedirects: true,
        maxRedirects: 5,
      },
    });

    // Enqueue scan through the SSOT queue service
    await enqueueScan(scan._id.toString());

    // Update schedule timestamp
    await ScanScheduleModel.findByIdAndUpdate(scheduleId, {
      lastRunAt: new Date(),
    });

    logger.info(
      { scheduleId, scanId: scan._id.toString(), targetId: schedule.targetId },
      'Scheduled scan dispatched successfully',
    );

    return { success: true, scanId: scan._id.toString() };
  } catch (err: any) {
    logger.error({ scheduleId, err: err?.message }, 'Failed executing scheduled scan');
    return { success: false, error: err?.message ?? 'Execution error', code: 'INTERNAL_ERROR' };
  }
}
