import { Queue } from 'bullmq';
import type { ConnectionOptions } from 'bullmq';

export const SCAN_QUEUE_NAME = 'scan-jobs';

/** The BullMQ job name used for all scan jobs. Must match the Worker's job name processor. */
export const SCAN_JOB_NAME = 'scan';

export function getRedisConnectionOptions(connection?: ConnectionOptions): ConnectionOptions {
  if (connection) return connection;
  const redisUrl = process.env['REDIS_URL'];
  if (redisUrl) {
    try {
      const parsed = new URL(redisUrl);
      return {
        host: parsed.hostname || 'localhost',
        port: parsed.port ? parseInt(parsed.port, 10) : 6379,
        password: parsed.password || undefined,
        username: parsed.username || undefined,
      };
    } catch {
      // Fallback
    }
  }
  return {
    host: process.env['REDIS_HOST'] ?? 'localhost',
    port: parseInt(process.env['REDIS_PORT'] ?? '6379', 10),
  };
}

export function createScanQueue(connection?: ConnectionOptions): Queue {
  const conn = getRedisConnectionOptions(connection);
  return new Queue(SCAN_QUEUE_NAME, { connection: conn });
}
