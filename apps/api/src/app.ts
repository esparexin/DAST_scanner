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
import { metricsRouter } from './routes/metrics.routes.js';
import { auditRouter } from './routes/audit.routes.js';
import { intelligenceRouter } from './routes/intelligence.routes.js';
import { webhookRouter } from './routes/webhook.routes.js';
import { scheduleRouter } from './routes/schedule.routes.js';
import { apiRateLimiter } from './middleware/rate-limiter.js';
import { tracingMiddleware } from './middleware/tracing.js';
import { httpMetricsMiddleware } from './middleware/metrics.js';
import { errorHandler } from './middleware/error-handler.js';

export function createApp() {
  const app = express();

  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: '10mb' }));
  app.use(tracingMiddleware);
  app.use(httpMetricsMiddleware);

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
  app.use('/api/metrics', metricsRouter);
  app.use('/api/audit', auditRouter);
  app.use('/api/admin/intelligence', intelligenceRouter);
  app.use('/api/webhooks', webhookRouter);
  app.use('/api/schedules', scheduleRouter);

  // Error handling
  app.use(errorHandler);

  return app;
}
