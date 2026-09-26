import { createApp } from './app.js';
import { connectDatabase } from '@securityscan/database';
import { createLogger } from '@securityscan/shared';
import { PORT } from './config.js';

const logger = createLogger('api');

async function main() {
  await connectDatabase();
  logger.info('Connected to MongoDB');

  const app = createApp();
  app.listen(PORT, () => {
    logger.info({ port: PORT }, 'API server started');
  });
}

main().catch((err) => {
  logger.fatal(err, 'Failed to start API server');
  process.exit(1);
});
