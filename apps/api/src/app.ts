import express from 'express';
import cors from 'cors';
import { healthRoutes } from './routes/health.routes.js';
import { authRoutes } from './routes/auth.routes.js';
import { projectRoutes } from './routes/project.routes.js';
import { targetRoutes } from './routes/target.routes.js';
import { scanRoutes } from './routes/scan.routes.js';
import { findingRoutes } from './routes/finding.routes.js';
import { reportRoutes } from './routes/report.routes.js';
import { endpointRoutes } from './routes/endpoint.routes.js';
import { authProfileRoutes } from './routes/auth-profile.routes.js';
import { apiSchemaRoutes } from './routes/api-schema.routes.js';
import { metricsRoutes } from './routes/metrics.routes.js';
import { errorHandler } from './middleware/error-handler.js';

export function createApp() {
  const app = express();

  app.use(cors());
  app.use(express.json({ limit: '10mb' }));

  // Routes
  app.use('/api/health', healthRoutes);
  app.use('/api/auth', authRoutes);
  app.use('/api/projects', projectRoutes);
  app.use('/api/targets', targetRoutes);
  app.use('/api/scans', scanRoutes);
  app.use('/api/findings', findingRoutes);
  app.use('/api/reports', reportRoutes);
  app.use('/api/endpoints', endpointRoutes);
  app.use('/api/auth-profiles', authProfileRoutes);
  app.use('/api/apis', apiSchemaRoutes);
  app.use('/api/metrics', metricsRoutes);

  // Error handling
  app.use(errorHandler);

  return app;
}
