import { Router } from 'express';
import { scanMetrics } from '@securityscan/metrics';

export const metricsRouter = Router();
export const metricsRoutes = metricsRouter;

metricsRouter.get('/', (_req, res) => {
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(scanMetrics.export());
});
