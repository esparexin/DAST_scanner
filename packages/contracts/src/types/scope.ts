import type { ScopeValidationResult } from '../enums.js';

export interface IScopeConfig {
  scanId: string;
  targetId: string;
  projectId: string;
  authorized: boolean;
  allowedHosts: string[];
  excludedHosts: string[];
  allowedPaths: string[];
  excludedPaths: string[];
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  maxRequests: number;
  maxCrawlDepth: number;
  maxResponseSize: number;
  maxScanDuration: number;
  timeoutPerRequest: number;
}

export interface IScopeValidation {
  result: ScopeValidationResult;
  url: string;
  reason?: string;
}

export interface IDryRunResult {
  target: string;
  allowedHosts: string[];
  excludedHosts: string[];
  allowedPaths: string[];
  excludedPaths: string[];
  scanProfile: string;
  authProfileCount: number;
  enabledCategories: string[];
  estimatedRequests: number;
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  maxCrawlDepth: number;
  maxScanDuration: number;
  valid: boolean;
  validationErrors: string[];
}
