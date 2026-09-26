import type { OrgRole, SubscriptionTier, TargetVerificationMethod } from '../enums.js';

export interface IOrganization {
  id: string;
  name: string;
  slug: string;
  tier: SubscriptionTier;
  createdAt: Date;
  updatedAt: Date;
}

export interface ICreateOrganization {
  name: string;
  slug?: string;
}

export interface IMembership {
  id: string;
  organizationId: string;
  userId: string;
  role: OrgRole;
  createdAt: Date;
  updatedAt: Date;
}

export interface ITargetOwnershipChallenge {
  targetId: string;
  hostname: string;
  token: string;
  method: TargetVerificationMethod;
  wellKnownPath: string;
  expectedContent: string;
  dnsRecordName: string;
  dnsExpectedValue: string;
  expiresAt: Date;
}

export interface IVerifyTargetRequest {
  method: TargetVerificationMethod;
}

export interface ITargetVerificationResult {
  verified: boolean;
  method: TargetVerificationMethod;
  details: string;
  verifiedAt?: Date;
}

export interface ITierQuotas {
  maxConcurrentScans: number;
  maxScansPerMonth: number;
  maxAuthorizedTargets: number;
  maxScanDurationSeconds: number;
  allowedProfiles: string[];
  customRulesAllowed: boolean;
}

export const SUBSCRIPTION_TIER_QUOTAS: Record<string, ITierQuotas> = {
  FREE: {
    maxConcurrentScans: 1,
    maxScansPerMonth: 10,
    maxAuthorizedTargets: 3,
    maxScanDurationSeconds: 1800,
    allowedProfiles: ['PASSIVE', 'QUICK', 'WEB_STANDARD'],
    customRulesAllowed: false,
  },
  DEVELOPER: {
    maxConcurrentScans: 3,
    maxScansPerMonth: 100,
    maxAuthorizedTargets: 25,
    maxScanDurationSeconds: 7200,
    allowedProfiles: ['PASSIVE', 'QUICK', 'WEB_STANDARD', 'API_STANDARD', 'AUTHENTICATED', 'PRODUCTION_SAFE'],
    customRulesAllowed: true,
  },
  TEAM: {
    maxConcurrentScans: 10,
    maxScansPerMonth: 500,
    maxAuthorizedTargets: 100,
    maxScanDurationSeconds: 21600,
    allowedProfiles: ['PASSIVE', 'QUICK', 'WEB_STANDARD', 'API_STANDARD', 'AUTHENTICATED', 'AUTHORIZATION', 'FULL_ASSESSMENT', 'CICD', 'PRODUCTION_SAFE'],
    customRulesAllowed: true,
  },
  ENTERPRISE: {
    maxConcurrentScans: 100,
    maxScansPerMonth: 10000,
    maxAuthorizedTargets: 1000,
    maxScanDurationSeconds: 86400,
    allowedProfiles: ['PASSIVE', 'QUICK', 'WEB_STANDARD', 'API_STANDARD', 'AUTHENTICATED', 'AUTHORIZATION', 'FULL_ASSESSMENT', 'CICD', 'PRODUCTION_SAFE'],
    customRulesAllowed: true,
  },
};
