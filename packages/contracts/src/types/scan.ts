import type { ScanStatus, ScanProfile } from '../enums.js';

export interface IScan {
  id: string;
  projectId: string;
  targetId: string;
  status: ScanStatus;
  profile: ScanProfile;
  dryRun: boolean;
  configuration: IScanConfiguration;
  progress: IScanProgress;
  startedAt?: Date;
  completedAt?: Date;
  cancelledAt?: Date;
  failedAt?: Date;
  failureReason?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface IScanConfiguration {
  profile: ScanProfile;
  authProfileIds: string[];
  enabledCategories: string[];
  excludedChecks: string[];
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  maxRequests: number;
  maxCrawlDepth: number;
  maxResponseSize: number;
  maxScanDuration: number;
  timeoutPerRequest: number;
  followRedirects: boolean;
  maxRedirects: number;
}

export interface IScanProgress {
  phase: ScanStatus;
  totalRequests: number;
  completedRequests: number;
  endpointsDiscovered: number;
  assetsDiscovered: number;
  checksExecuted: number;
  checksTotal: number;
  findingsTotal: number;
  findingsConfirmed: number;
  errors: number;
}

export interface ICreateScan {
  projectId: string;
  targetId: string;
  profile?: ScanProfile;
  dryRun?: boolean;
  authProfileIds?: string[];
  enabledCategories?: string[];
  excludedChecks?: string[];
}

// Valid state transitions
export const SCAN_STATE_TRANSITIONS: Record<ScanStatus, ScanStatus[]> = {
  [ScanStatus.CREATED]: [ScanStatus.VALIDATING, ScanStatus.CANCELLED],
  [ScanStatus.VALIDATING]: [ScanStatus.QUEUED, ScanStatus.FAILED, ScanStatus.CANCELLED],
  [ScanStatus.QUEUED]: [ScanStatus.DISCOVERING, ScanStatus.FAILED, ScanStatus.CANCELLED],
  [ScanStatus.DISCOVERING]: [
    ScanStatus.CRAWLING,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMEOUT,
  ],
  [ScanStatus.CRAWLING]: [
    ScanStatus.PASSIVE_ANALYSIS,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMEOUT,
  ],
  [ScanStatus.PASSIVE_ANALYSIS]: [
    ScanStatus.ACTIVE_TESTING,
    ScanStatus.REPORTING,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMEOUT,
  ],
  [ScanStatus.ACTIVE_TESTING]: [
    ScanStatus.API_TESTING,
    ScanStatus.VERIFYING,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMEOUT,
  ],
  [ScanStatus.API_TESTING]: [
    ScanStatus.VERIFYING,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMEOUT,
  ],
  [ScanStatus.VERIFYING]: [
    ScanStatus.EVIDENCE_COLLECTION,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMEOUT,
  ],
  [ScanStatus.EVIDENCE_COLLECTION]: [
    ScanStatus.REPORTING,
    ScanStatus.FAILED,
    ScanStatus.CANCELLED,
    ScanStatus.TIMEOUT,
  ],
  [ScanStatus.REPORTING]: [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED],
  [ScanStatus.COMPLETED]: [],
  [ScanStatus.FAILED]: [],
  [ScanStatus.CANCELLED]: [],
  [ScanStatus.TIMEOUT]: [],
};
