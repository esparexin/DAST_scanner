import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { AuthorizationState, TargetEnvironment } from '@securityscan/contracts';

export interface ITargetScopeDoc {
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

export interface ITargetChallengeDoc {
  token: string;
  method: string;
  wellKnownPath: string;
  expectedContent: string;
  dnsRecordName: string;
  dnsExpectedValue: string;
  expiresAt: Date;
}

export interface ITargetDocument extends Document {
  projectId: Types.ObjectId;
  name: string;
  baseUrl: string;
  environment: TargetEnvironment;
  authorization: AuthorizationState;
  authorizedAt?: Date;
  authorizedBy?: Types.ObjectId;
  scope: ITargetScopeDoc;
  verificationChallenge?: ITargetChallengeDoc;
  createdAt: Date;
  updatedAt: Date;
}

const TargetScopeSchema = new Schema<ITargetScopeDoc>(
  {
    allowedHosts: { type: [String], required: true },
    excludedHosts: { type: [String], default: [] },
    allowedPaths: { type: [String], default: [] },
    excludedPaths: { type: [String], default: [] },
    maxRequestsPerSecond: { type: Number, default: 10 },
    maxConcurrency: { type: Number, default: 5 },
    maxRequests: { type: Number, default: 10000 },
    maxCrawlDepth: { type: Number, default: 5 },
    maxResponseSize: { type: Number, default: 10 * 1024 * 1024 },
    maxScanDuration: { type: Number, default: 3600 },
    timeoutPerRequest: { type: Number, default: 30 },
  },
  { _id: false },
);

const TargetChallengeSchema = new Schema<ITargetChallengeDoc>(
  {
    token: { type: String, required: true },
    method: { type: String, required: true },
    wellKnownPath: { type: String, required: true },
    expectedContent: { type: String, required: true },
    dnsRecordName: { type: String, required: true },
    dnsExpectedValue: { type: String, required: true },
    expiresAt: { type: Date, required: true },
  },
  { _id: false },
);

const TargetSchema = new Schema<ITargetDocument>(
  {
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    name: { type: String, required: true, trim: true },
    baseUrl: { type: String, required: true },
    environment: {
      type: String,
      enum: Object.values(TargetEnvironment),
      default: TargetEnvironment.TESTING,
    },
    authorization: {
      type: String,
      enum: Object.values(AuthorizationState),
      default: AuthorizationState.PENDING,
    },
    authorizedAt: { type: Date },
    authorizedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    scope: { type: TargetScopeSchema, required: true },
    verificationChallenge: { type: TargetChallengeSchema },
  },
  { timestamps: true },
);

export const TargetModel = mongoose.model<ITargetDocument>('Target', TargetSchema);
