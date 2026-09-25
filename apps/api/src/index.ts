import { createApp } from './app.js';
import { connectDatabase } from '@securityscan/database';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('api');
const port = parseInt(process.env['PORT'] ?? '3001', 10);

async function main() {
  await connectDatabase();
  logger.info('Connected to MongoDB');

  const app = createApp();
  app.listen(port, () => {
    logger.info({ port }, 'API server started');
  });
}

main().catch((err) => {
  logger.fatal(err, 'Failed to start API server');
  process.exit(1);
});
