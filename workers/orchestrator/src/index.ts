import { Worker, type Job } from 'bullmq';
import { connectDatabase, disconnectDatabase } from '@securityscan/database';
import { SCAN_QUEUE_NAME, getRedisConnectionOptions } from '@securityscan/scanner-core';
import { createLogger } from '@securityscan/shared';
import { scanMetrics } from '@securityscan/metrics';
import { processScan } from './scan-processor.js';

const logger = createLogger('scan-worker');

export async function startWorker(): Promise<Worker> {
  await connectDatabase();
  logger.info('Worker connected to MongoDB');

  const worker = new Worker(
    SCAN_QUEUE_NAME,
    async (job: Job) => {
      const traceId = job.data?.traceId;
      logger.info({ jobId: job.id, scanId: job.data.scanId, traceId }, 'Processing scan job');
      scanMetrics.incrementGauge('securityscan_worker_jobs_active');
      try {
        await processScan(job.data.scanId as string, { traceId });
      } finally {
        scanMetrics.incrementGauge('securityscan_worker_jobs_active', {}, -1);
      }
    },
    {
      connection: getRedisConnectionOptions(),
      concurrency: parseInt(process.env['MAX_CONCURRENT_SCANS'] ?? '2', 10),
    },
  );

  worker.on('completed', (job: Job) => {
    logger.info({ jobId: job.id }, 'Scan job completed');
  });

  worker.on('failed', (job: Job | undefined, error: Error) => {
    logger.error({ jobId: job?.id, error: error.message }, 'Scan job failed');
  });

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down worker gracefully...');
    try {
      await worker.close();
      logger.info('BullMQ worker closed');
      await disconnectDatabase();
      logger.info('Database disconnected');
      process.exit(0);
    } catch (err) {
      logger.error(err, 'Error during worker shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  logger.info('Scan worker started, waiting for jobs...');
  return worker;
}

if (process.env['NODE_ENV'] !== 'test') {
  startWorker().catch((err) => {
    logger.fatal(err, 'Worker failed to start');
    process.exit(1);
  });
}

