import { Queue } from 'bullmq';
import { SCAN_QUEUE_NAME } from '@securityscan/scanner-core';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('queue-service');

let scanQueue: Queue | null = null;

function getQueue(): Queue {
  if (!scanQueue) {
    scanQueue = new Queue(SCAN_QUEUE_NAME, {
      connection: {
        host: process.env['REDIS_HOST'] ?? 'localhost',
        port: parseInt(process.env['REDIS_PORT'] ?? '6379', 10),
      },
    });
  }
  return scanQueue;
}

export async function enqueueScan(scanId: string): Promise<void> {
  try {
    const queue = getQueue();
    await queue.add('scan', { scanId }, {
      jobId: `scan-${scanId}`,
      removeOnComplete: 100,
      removeOnFail: 100,
    });
    logger.info({ scanId }, 'Scan enqueued');
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
