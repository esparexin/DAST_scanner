import { z } from 'zod';
import {
  DEFAULT_MAX_REQUESTS_PER_SECOND,
  DEFAULT_MAX_CONCURRENCY,
  DEFAULT_MAX_REQUESTS,
  DEFAULT_MAX_CRAWL_DEPTH,
  DEFAULT_MAX_RESPONSE_SIZE,
  DEFAULT_MAX_SCAN_DURATION,
  DEFAULT_TIMEOUT_PER_REQUEST,
  MAX_REQUESTS_PER_SECOND_LIMIT,
  MAX_CONCURRENCY_LIMIT,
  MAX_REQUESTS_LIMIT,
  MAX_CRAWL_DEPTH_LIMIT,
  MAX_RESPONSE_SIZE_LIMIT,
  MAX_SCAN_DURATION_LIMIT,
  MAX_TIMEOUT_PER_REQUEST_LIMIT,
} from '../constants.js';

const hostPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

export const ScopeSchema = z.object({
  allowedHosts: z
    .array(z.string().regex(hostPattern, 'Invalid hostname'))
    .min(1, 'At least one allowed host is required'),
  excludedHosts: z
    .array(z.string().regex(hostPattern, 'Invalid hostname'))
    .optional()
    .default([]),
  allowedPaths: z.array(z.string().startsWith('/')).optional().default([]),
  excludedPaths: z.array(z.string().startsWith('/')).optional().default([]),
  maxRequestsPerSecond: z
    .number()
    .int()
    .min(1)
    .max(MAX_REQUESTS_PER_SECOND_LIMIT)
    .optional()
    .default(DEFAULT_MAX_REQUESTS_PER_SECOND),
  maxConcurrency: z
    .number()
    .int()
    .min(1)
    .max(MAX_CONCURRENCY_LIMIT)
    .optional()
    .default(DEFAULT_MAX_CONCURRENCY),
  maxRequests: z
    .number()
    .int()
    .min(1)
    .max(MAX_REQUESTS_LIMIT)
    .optional()
    .default(DEFAULT_MAX_REQUESTS),
  maxCrawlDepth: z
    .number()
    .int()
    .min(1)
    .max(MAX_CRAWL_DEPTH_LIMIT)
    .optional()
    .default(DEFAULT_MAX_CRAWL_DEPTH),
  maxResponseSize: z
    .number()
    .int()
    .min(1024)
    .max(MAX_RESPONSE_SIZE_LIMIT)
    .optional()
    .default(DEFAULT_MAX_RESPONSE_SIZE),
  maxScanDuration: z
    .number()
    .int()
    .min(60)
    .max(MAX_SCAN_DURATION_LIMIT)
    .optional()
    .default(DEFAULT_MAX_SCAN_DURATION),
  timeoutPerRequest: z
    .number()
    .int()
    .min(5)
    .max(MAX_TIMEOUT_PER_REQUEST_LIMIT)
    .optional()
    .default(DEFAULT_TIMEOUT_PER_REQUEST),
});

export type ScopeInput = z.infer<typeof ScopeSchema>;
