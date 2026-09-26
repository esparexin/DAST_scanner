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
