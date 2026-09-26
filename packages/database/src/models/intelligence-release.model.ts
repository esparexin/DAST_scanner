import mongoose, { Schema, type Document, type Types } from 'mongoose';

export type IntelligenceReleaseStatus = 'ACTIVE' | 'SUPERSEDED' | 'ROLLED_BACK';

export interface IIntelligenceReleaseDocument extends Document {
  releaseVersion: string;
  packageHash: string;
  signatureVerified: boolean;
  ruleCount: number;
  payloadCount: number;
  manifest: Record<string, unknown>;
  diffSummary?: string;
  status: IntelligenceReleaseStatus;
  appliedBy?: Types.ObjectId;
  installedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

const IntelligenceReleaseSchema = new Schema<IIntelligenceReleaseDocument>(
  {
    releaseVersion: { type: String, required: true, unique: true, index: true },
    packageHash: { type: String, required: true },
    signatureVerified: { type: Boolean, required: true, default: false },
    ruleCount: { type: Number, required: true, default: 0 },
    payloadCount: { type: Number, required: true, default: 0 },
    manifest: { type: Schema.Types.Mixed, required: true },
    diffSummary: { type: String, default: '' },
    status: {
      type: String,
      enum: ['ACTIVE', 'SUPERSEDED', 'ROLLED_BACK'],
      default: 'ACTIVE',
      index: true,
    },
    appliedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    installedAt: { type: Date, default: Date.now },
  },
  { timestamps: true },
);

export const IntelligenceReleaseModel = mongoose.model<IIntelligenceReleaseDocument>(
  'IntelligenceRelease',
  IntelligenceReleaseSchema,
);
