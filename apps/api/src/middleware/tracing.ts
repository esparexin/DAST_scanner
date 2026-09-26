import type { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'node:crypto';

export interface TracedRequest extends Request {
  traceId?: string;
  startTime?: number;
}

export function tracingMiddleware(req: Request, res: Response, next: NextFunction): void {
  const headerTraceId =
    (req.headers['x-trace-id'] as string) ||
    (req.headers['x-request-id'] as string);

  const traceId = headerTraceId && headerTraceId.trim().length > 0
    ? headerTraceId.trim()
    : randomUUID();

  (req as TracedRequest).traceId = traceId;
  (req as TracedRequest).startTime = Date.now();

  res.setHeader('X-Trace-Id', traceId);
  res.setHeader('X-Request-Id', traceId);

  next();
}
