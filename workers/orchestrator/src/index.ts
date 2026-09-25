import { Worker } from 'bullmq';
import { connectDatabase } from '@securityscan/database';
import { SCAN_QUEUE_NAME } from '@securityscan/scanner-core';
import { createLogger } from '@securityscan/shared';
import { processScan } from './scan-processor.js';

const logger = createLogger('scan-worker');

async function main() {
  await connectDatabase();
  logger.info('Worker connected to MongoDB');

  const worker = new Worker(
    SCAN_QUEUE_NAME,
    async (job) => {
      logger.info({ jobId: job.id, scanId: job.data.scanId }, 'Processing scan job');
      await processScan(job.data.scanId as string);
    },
    {
      connection: {
        host: process.env['REDIS_HOST'] ?? 'localhost',
        port: parseInt(process.env['REDIS_PORT'] ?? '6379', 10),
      },
      concurrency: 2,
    },
  );

  worker.on('completed', (job) => {
    logger.info({ jobId: job.id }, 'Scan job completed');
  });

  worker.on('failed', (job, error) => {
    logger.error({ jobId: job?.id, error: error.message }, 'Scan job failed');
  });

  logger.info('Scan worker started, waiting for jobs...');
}

main().catch((err) => {
  logger.fatal(err, 'Worker failed to start');
  process.exit(1);
});
