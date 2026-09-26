import { Router } from 'express';
import { isDatabaseConnected } from '@securityscan/database';

export const healthRouter = Router();

healthRouter.get('/', (_req, res) => {
  const healthy = isDatabaseConnected();
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'unhealthy',
    mongodb: healthy ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
  });
});
