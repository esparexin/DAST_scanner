import { Redis } from 'ioredis';
import type { ScanStatus } from '@securityscan/contracts';
import { getRedisConnectionOptions } from './queue.js';

export const SCAN_EVENTS_CHANNEL = 'scan:progress:events';

export interface ScanProgressEvent {
  scanId: string;
  phase: ScanStatus;
  totalRequests?: number;
  completedRequests?: number;
  endpointsDiscovered?: number;
  findingsTotal?: number;
  findingsConfirmed?: number;
  timestamp: string;
  message?: string;
}

export function formatScanProgressEvent(
  scanId: string,
  phase: ScanStatus,
  extra?: Partial<ScanProgressEvent>,
): ScanProgressEvent {
  return {
    scanId,
    phase,
    timestamp: new Date().toISOString(),
    ...extra,
  };
}

export function createRedisClient(): Redis {
  const opts = getRedisConnectionOptions() as Record<string, any>;
  return new Redis({
    host: (opts['host'] as string) ?? 'localhost',
    port: (opts['port'] as number) ?? 6379,
    password: opts['password'] as string | undefined,
    username: opts['username'] as string | undefined,
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    lazyConnect: true,
  });
}

export async function publishScanProgress(client: Redis, event: ScanProgressEvent): Promise<number> {
  return client.publish(SCAN_EVENTS_CHANNEL, JSON.stringify(event));
}
