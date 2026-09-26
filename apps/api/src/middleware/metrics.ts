import type { Request, Response, NextFunction } from 'express';
import { scanMetrics } from '@securityscan/metrics';

export function httpMetricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();

  res.on('finish', () => {
    const durationSeconds = (Date.now() - start) / 1000;
    const method = req.method;
    const statusCode = String(res.statusCode);

    scanMetrics.incrementCounter('securityscan_api_requests_total', {
      method,
      status: statusCode,
    });

    scanMetrics.observeHistogram('securityscan_api_request_duration_seconds', durationSeconds, {
      method,
      status: statusCode,
    });
  });

  next();
}
