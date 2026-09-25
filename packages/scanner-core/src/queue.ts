import { Queue } from 'bullmq';
import type { ConnectionOptions } from 'bullmq';

export const SCAN_QUEUE_NAME = 'scan-jobs';

export function createScanQueue(connection?: ConnectionOptions): Queue {
  const conn = connection ?? {
    host: process.env['REDIS_HOST'] ?? 'localhost',
    port: parseInt(process.env['REDIS_PORT'] ?? '6379', 10),
  };
  return new Queue(SCAN_QUEUE_NAME, { connection: conn });
}
