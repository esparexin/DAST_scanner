import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { ScanStatus, ScanProfile } from '@securityscan/contracts';

export interface IScanProgressDoc {
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

export interface IScanConfigDoc {
  profile: ScanProfile;
  authProfileIds: Types.ObjectId[];
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

export interface IScanDocument extends Document {
  projectId: Types.ObjectId;
  targetId: Types.ObjectId;
  status: ScanStatus;
  profile: ScanProfile;
  dryRun: boolean;
  configuration: IScanConfigDoc;
  progress: IScanProgressDoc;
  startedAt?: Date;
  completedAt?: Date;
  cancelledAt?: Date;
  failedAt?: Date;
  failureReason?: string;
  createdAt: Date;
  updatedAt: Date;
}

const ScanProgressSchema = new Schema<IScanProgressDoc>(
  {
    phase: { type: String, enum: Object.values(ScanStatus), default: ScanStatus.CREATED },
    totalRequests: { type: Number, default: 0 },
    completedRequests: { type: Number, default: 0 },
    endpointsDiscovered: { type: Number, default: 0 },
    assetsDiscovered: { type: Number, default: 0 },
    checksExecuted: { type: Number, default: 0 },
    checksTotal: { type: Number, default: 0 },
    findingsTotal: { type: Number, default: 0 },
    findingsConfirmed: { type: Number, default: 0 },
    errors: { type: Number, default: 0 },
  },
  { _id: false, suppressReservedKeysWarning: true },
);

const ScanConfigSchema = new Schema<IScanConfigDoc>(
  {
    profile: { type: String, enum: Object.values(ScanProfile), default: ScanProfile.STANDARD },
    authProfileIds: [{ type: Schema.Types.ObjectId, ref: 'AuthProfile' }],
    enabledCategories: { type: [String], default: [] },
    excludedChecks: { type: [String], default: [] },
    maxRequestsPerSecond: { type: Number, default: 10 },
    maxConcurrency: { type: Number, default: 5 },
    maxRequests: { type: Number, default: 10000 },
    maxCrawlDepth: { type: Number, default: 5 },
    maxResponseSize: { type: Number, default: 10 * 1024 * 1024 },
    maxScanDuration: { type: Number, default: 3600 },
    timeoutPerRequest: { type: Number, default: 30 },
    followRedirects: { type: Boolean, default: true },
    maxRedirects: { type: Number, default: 10 },
  },
  { _id: false },
);

const ScanSchema = new Schema<IScanDocument>(
  {
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    targetId: { type: Schema.Types.ObjectId, ref: 'Target', required: true, index: true },
    status: { type: String, enum: Object.values(ScanStatus), default: ScanStatus.CREATED },
    profile: { type: String, enum: Object.values(ScanProfile), default: ScanProfile.STANDARD },
    dryRun: { type: Boolean, default: false },
    configuration: { type: ScanConfigSchema, required: true },
    progress: { type: ScanProgressSchema, default: () => ({}) },
    startedAt: Date,
    completedAt: Date,
    cancelledAt: Date,
    failedAt: Date,
    failureReason: String,
  },
  { timestamps: true },
);

ScanSchema.index({ status: 1 });
ScanSchema.index({ projectId: 1, createdAt: -1 });

export const ScanModel = mongoose.model<IScanDocument>('Scan', ScanSchema);
