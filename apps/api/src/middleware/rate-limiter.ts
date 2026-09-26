import type { Request, Response, NextFunction } from 'express';
import type { Redis } from 'ioredis';
import { createLogger } from '@securityscan/shared';
import { createRedisClient } from '@securityscan/scanner-core';

const logger = createLogger('rate-limiter');

export interface RateLimiterOptions {
  windowSeconds?: number;
  maxRequests: number;
  keyPrefix?: string;
  keyGenerator?: (req: Request) => string;
  redisClient?: Redis | null;
}

const inMemoryStore = new Map<string, number[]>();

let sharedRedis: Redis | null = null;

function getSharedRedis(): Redis | null {
  if (process.env['NODE_ENV'] === 'test' && !process.env['FORCE_REDIS']) {
    return null;
  }
  if (!sharedRedis) {
    try {
      sharedRedis = createRedisClient();
      sharedRedis.on('error', (err) => {
        logger.debug({ err: err.message }, 'Redis rate-limiter connection error (falling back to in-memory)');
      });
    } catch {
      sharedRedis = null;
    }
  }
  return sharedRedis;
}

export function clearInMemoryRateLimits(): void {
  inMemoryStore.clear();
}

export function createRateLimiter(options: RateLimiterOptions) {
  const windowSeconds = options.windowSeconds ?? 60;
  const maxRequests = options.maxRequests;
  const keyPrefix = options.keyPrefix ?? 'rl';
  const defaultKeyGen = (req: Request) =>
    (req as any).userId ?? req.ip ?? req.socket?.remoteAddress ?? 'unknown';
  const keyGen = options.keyGenerator ?? defaultKeyGen;

  return async function rateLimiterMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    const identifier = keyGen(req);
    const key = `${keyPrefix}:${identifier}`;
    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    const windowStart = now - windowMs;

    let count = 0;
    const redis = options.redisClient !== undefined ? options.redisClient : getSharedRedis();

    if (redis && redis.status === 'ready') {
      try {
        const pipeline = redis.pipeline();
        pipeline.zremrangebyscore(key, 0, windowStart);
        pipeline.zadd(key, now, `${now}-${Math.random().toString(36).slice(2, 8)}`);
        pipeline.zcard(key);
        pipeline.expire(key, windowSeconds);

        const results = await pipeline.exec();
        count = (results?.[2]?.[1] as number) ?? 1;
      } catch (redisErr: any) {
        logger.debug({ key, err: redisErr?.message }, 'Redis rate-limiter failed; falling back to in-memory');
        count = recordInMemory(key, now, windowStart);
      }
    } else {
      count = recordInMemory(key, now, windowStart);
    }

    const remaining = Math.max(0, maxRequests - count);

    res.setHeader('RateLimit-Limit', maxRequests);
    res.setHeader('RateLimit-Remaining', remaining);
    res.setHeader('RateLimit-Reset', windowSeconds);

    if (count > maxRequests) {
      res.setHeader('Retry-After', windowSeconds);
      res.status(429).json({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          details: {
            retryAfterSeconds: windowSeconds,
            maxRequests,
            windowSeconds,
          },
        },
      });
      return;
    }

    next();
  };
}

function recordInMemory(key: string, now: number, windowStart: number): number {
  const timestamps = inMemoryStore.get(key) || [];
  const valid = timestamps.filter((t) => t > windowStart);
  valid.push(now);
  inMemoryStore.set(key, valid);
  return valid.length;
}

// Preset Rate Limiters
export const authRateLimiter = createRateLimiter({
  windowSeconds: 60,
  maxRequests: 15,
  keyPrefix: 'rl:auth',
});

export const scanRateLimiter = createRateLimiter({
  windowSeconds: 60,
  maxRequests: 30,
  keyPrefix: 'rl:scan',
  keyGenerator: (req) => (req as any).userId ?? req.ip ?? req.socket?.remoteAddress ?? 'anonymous',
});

export const apiRateLimiter = createRateLimiter({
  windowSeconds: 60,
  maxRequests: 300,
  keyPrefix: 'rl:api',
});
