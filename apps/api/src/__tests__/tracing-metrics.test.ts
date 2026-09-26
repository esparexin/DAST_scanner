import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { tracingMiddleware, type TracedRequest } from '../middleware/tracing.js';
import { httpMetricsMiddleware } from '../middleware/metrics.js';
import { scanMetrics } from '@securityscan/metrics';

describe('Tracing & HTTP Observability Middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('tracingMiddleware', () => {
    it('generates a new trace ID when headers are absent', () => {
      const req: Partial<TracedRequest> = { headers: {} };
      const headersSet: Record<string, string> = {};
      const res: any = {
        setHeader: vi.fn((k, v) => {
          headersSet[k] = v;
        }),
      };
      const next = vi.fn();

      tracingMiddleware(req as any, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.traceId).toBeDefined();
      expect(req.traceId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      expect(headersSet['X-Trace-Id']).toBe(req.traceId);
      expect(headersSet['X-Request-Id']).toBe(req.traceId);
    });

    it('propagates incoming x-trace-id or x-request-id', () => {
      const incomingId = 'client-trace-abc-123';
      const req: Partial<TracedRequest> = {
        headers: { 'x-trace-id': incomingId },
      };
      const headersSet: Record<string, string> = {};
      const res: any = {
        setHeader: vi.fn((k, v) => {
          headersSet[k] = v;
        }),
      };
      const next = vi.fn();

      tracingMiddleware(req as any, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.traceId).toBe(incomingId);
      expect(headersSet['X-Trace-Id']).toBe(incomingId);
      expect(headersSet['X-Request-Id']).toBe(incomingId);
    });
  });

  describe('httpMetricsMiddleware', () => {
    it('records API request duration and counter on response finish', () => {
      const observeSpy = vi.spyOn(scanMetrics, 'observeHistogram');
      const counterSpy = vi.spyOn(scanMetrics, 'incrementCounter');

      const req: any = {
        method: 'POST',
        baseUrl: '/api/scans',
        path: '/api/scans',
      };

      class MockResponse extends EventEmitter {
        statusCode = 201;
      }
      const res = new MockResponse();
      const next = vi.fn();

      httpMetricsMiddleware(req, res as any, next);
      expect(next).toHaveBeenCalledTimes(1);

      // Trigger finish event
      res.emit('finish');

      expect(counterSpy).toHaveBeenCalledWith(
        'securityscan_api_requests_total',
        expect.objectContaining({ method: 'POST', status: '201' }),
      );
      expect(observeSpy).toHaveBeenCalledWith(
        'securityscan_api_request_duration_seconds',
        expect.any(Number),
        expect.objectContaining({ method: 'POST', status: '201' }),
      );
    });
  });

  describe('Prometheus Metrics Export', () => {
    it('exports Prometheus formatted text containing phase and latency metrics', () => {
      const metricsText = scanMetrics.export();
      expect(metricsText).toContain('# HELP securityscan_phase_duration_seconds');
      expect(metricsText).toContain('# TYPE securityscan_phase_duration_seconds histogram');
      expect(metricsText).toContain('# HELP securityscan_api_request_duration_seconds');
      expect(metricsText).toContain('# HELP securityscan_worker_jobs_active');
    });
  });
});
