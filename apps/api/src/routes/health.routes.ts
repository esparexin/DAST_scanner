import { Router } from 'express';
import mongoose from 'mongoose';

export const healthRouter = Router();

healthRouter.get('/', (_req, res) => {
  const mongoState = mongoose.connection.readyState;
  const healthy = mongoState === 1;
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'unhealthy',
    mongodb: mongoState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
  });
});
