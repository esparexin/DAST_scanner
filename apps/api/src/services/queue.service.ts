import { Queue } from 'bullmq';
import { SCAN_QUEUE_NAME, SCAN_JOB_NAME, getRedisConnectionOptions } from '@securityscan/scanner-core';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('queue-service');

let scanQueue: Queue | null = null;

function getQueue(): Queue {
  if (!scanQueue) {
    scanQueue = new Queue(SCAN_QUEUE_NAME, {
      connection: getRedisConnectionOptions(),
    });
  }
  return scanQueue;
}

export async function enqueueScan(
  scanId: string,
  metadata?: { traceId?: string },
): Promise<void> {
  try {
    const queue = getQueue();
    const traceId = metadata?.traceId;
    await queue.add(
      SCAN_JOB_NAME,
      { scanId, traceId },
      {
        jobId: `scan-${scanId}`,
        removeOnComplete: 100,
        removeOnFail: 100,
      },
    );
    logger.info({ scanId, traceId }, 'Scan enqueued');
  } catch (error) {
    // Queue might not be available in dev; log but don't fail
    logger.warn({ scanId, error: (error as Error).message }, 'Failed to enqueue scan (Redis may be unavailable)');
  }
}

export async function cancelScanJobs(scanId: string): Promise<void> {
  try {
    const queue = getQueue();
    const job = await queue.getJob(`scan-${scanId}`);
    if (job) {
      await job.remove();
      logger.info({ scanId }, 'Scan job removed from queue');
    }
  } catch (error) {
    logger.warn({ scanId, error: (error as Error).message }, 'Failed to cancel scan jobs');
  }
}
