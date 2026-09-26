import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createRateLimiter, clearInMemoryRateLimits } from '../middleware/rate-limiter.js';
import { createApp } from '../app.js';

describe('Production Rate Limiter & Security Hardening', () => {
  beforeEach(() => {
    clearInMemoryRateLimits();
    vi.clearAllMocks();
  });

  it('allows requests within maxRequests and sets rate limit headers', async () => {
    const limiter = createRateLimiter({
      windowSeconds: 60,
      maxRequests: 3,
      keyPrefix: 'test-limit',
      keyGenerator: () => 'user-123',
    });

    const headers: Record<string, string | number> = {};
    const res: any = {
      setHeader: vi.fn((k, v) => {
        headers[k] = v;
      }),
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    // 1st request
    await limiter({} as any, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(headers['RateLimit-Limit']).toBe(3);
    expect(headers['RateLimit-Remaining']).toBe(2);

    // 2nd request
    await limiter({} as any, res, next);
    expect(next).toHaveBeenCalledTimes(2);
    expect(headers['RateLimit-Remaining']).toBe(1);

    // 3rd request
    await limiter({} as any, res, next);
    expect(next).toHaveBeenCalledTimes(3);
    expect(headers['RateLimit-Remaining']).toBe(0);
  });

  it('blocks requests exceeding maxRequests with 429 and Retry-After', async () => {
    const limiter = createRateLimiter({
      windowSeconds: 60,
      maxRequests: 2,
      keyPrefix: 'test-block',
      keyGenerator: () => 'ip-1.2.3.4',
    });

    const res: any = {
      setHeader: vi.fn(),
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    // 2 allowed requests
    await limiter({} as any, res, next);
    await limiter({} as any, res, next);
    expect(next).toHaveBeenCalledTimes(2);

    // 3rd request exceeds limit
    await limiter({} as any, res, next);
    expect(next).toHaveBeenCalledTimes(2); // not called again
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.setHeader).toHaveBeenCalledWith('Retry-After', 60);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.objectContaining({
          code: 'RATE_LIMIT_EXCEEDED',
        }),
      }),
    );
  });

  it('uses Redis pipeline when redis client is ready', async () => {
    const mockPipeline = {
      zremrangebyscore: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, 0],
        [null, 1],
        [null, 1], // zcard count = 1
        [null, 1],
      ]),
    };

    const mockRedis: any = {
      status: 'ready',
      pipeline: vi.fn().mockReturnValue(mockPipeline),
    };

    const limiter = createRateLimiter({
      windowSeconds: 30,
      maxRequests: 5,
      keyPrefix: 'test-redis',
      keyGenerator: () => 'tenant-99',
      redisClient: mockRedis,
    });

    const res: any = {
      setHeader: vi.fn(),
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    await limiter({} as any, res, next);

    expect(mockRedis.pipeline).toHaveBeenCalled();
    expect(mockPipeline.zremrangebyscore).toHaveBeenCalled();
    expect(mockPipeline.zadd).toHaveBeenCalled();
    expect(mockPipeline.zcard).toHaveBeenCalled();
    expect(mockPipeline.expire).toHaveBeenCalledWith('test-redis:tenant-99', 30);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.setHeader).toHaveBeenCalledWith('RateLimit-Remaining', 4);
  });

  it('gracefully degrades to in-memory store if Redis pipeline fails', async () => {
    const mockPipeline = {
      zremrangebyscore: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockRejectedValue(new Error('Connection refused')),
    };

    const mockRedis: any = {
      status: 'ready',
      pipeline: vi.fn().mockReturnValue(mockPipeline),
    };

    const limiter = createRateLimiter({
      windowSeconds: 30,
      maxRequests: 5,
      keyPrefix: 'test-fallback',
      keyGenerator: () => 'tenant-failover',
      redisClient: mockRedis,
    });

    const res: any = {
      setHeader: vi.fn(),
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    await limiter({} as any, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.setHeader).toHaveBeenCalledWith('RateLimit-Remaining', 4);
  });

  it('enforces helmet security middleware in createApp', () => {
    const app = createApp();
    const stack = (app as any)._router?.stack || [];
    // Verify helmet middleware functions are registered in express router stack
    const hasHelmetMiddleware = stack.some((layer: any) =>
      ['helmet', 'xXssProtection', 'xFrameOptions', 'hidePoweredBy'].some((name) =>
        layer.name?.toLowerCase().includes(name.toLowerCase()),
      ),
    );
    expect(hasHelmetMiddleware).toBe(true);
  });
});
