import type {
  AuthorizationState,
  TargetEnvironment,
} from '../enums.js';

export interface ITarget {
  id: string;
  projectId: string;
  name: string;
  baseUrl: string;
  environment: TargetEnvironment;
  authorization: AuthorizationState;
  authorizedAt?: Date;
  authorizedBy?: string;
  scope: ITargetScope;
  createdAt: Date;
  updatedAt: Date;
}

export interface ITargetScope {
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

export interface ICreateTarget {
  projectId: string;
  name: string;
  baseUrl: string;
  environment?: TargetEnvironment;
  scope: ICreateTargetScope;
}

export interface ICreateTargetScope {
  allowedHosts: string[];
  excludedHosts?: string[];
  allowedPaths?: string[];
  excludedPaths?: string[];
  maxRequestsPerSecond?: number;
  maxConcurrency?: number;
  maxRequests?: number;
  maxCrawlDepth?: number;
  maxResponseSize?: number;
  maxScanDuration?: number;
  timeoutPerRequest?: number;
}

export interface IUpdateTarget {
  name?: string;
  baseUrl?: string;
  environment?: TargetEnvironment;
  authorization?: AuthorizationState;
  scope?: Partial<ITargetScope>;
}
