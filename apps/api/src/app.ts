import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { healthRouter } from './routes/health.routes.js';
import { authRouter } from './routes/auth.routes.js';
import { projectRouter } from './routes/project.routes.js';
import { organizationRouter } from './routes/organization.routes.js';
import { targetRouter } from './routes/target.routes.js';
import { scanRouter } from './routes/scan.routes.js';
import { findingRouter } from './routes/finding.routes.js';
import { reportRouter } from './routes/report.routes.js';
import { endpointRouter } from './routes/endpoint.routes.js';
import { authProfileRouter } from './routes/auth-profile.routes.js';
import { apiSchemaRouter } from './routes/api-schema.routes.js';
import { metricsRoutes } from './routes/metrics.routes.js';
import { auditRoutes } from './routes/audit.routes.js';
import { intelligenceRouter } from './routes/intelligence.routes.js';
import { apiRateLimiter } from './middleware/rate-limiter.js';
import { errorHandler } from './middleware/error-handler.js';

export function createApp() {
  const app = express();

  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: '10mb' }));

  if (process.env['NODE_ENV'] !== 'test') {
    app.use('/api', apiRateLimiter);
  }

  // Routes
  app.use('/api/health', healthRouter);
  app.use('/api/auth', authRouter);
  app.use('/api/projects', projectRouter);
  app.use('/api/organizations', organizationRouter);
  app.use('/api/targets', targetRouter);
  app.use('/api/scans', scanRouter);
  app.use('/api/findings', findingRouter);
  app.use('/api/reports', reportRouter);
  app.use('/api/endpoints', endpointRouter);
  app.use('/api/auth-profiles', authProfileRouter);
  app.use('/api/apis', apiSchemaRouter);
  app.use('/api/metrics', metricsRoutes);
  app.use('/api/audit', auditRoutes);
  app.use('/api/admin/intelligence', intelligenceRouter);

  // Error handling
  app.use(errorHandler);

  return app;
}
