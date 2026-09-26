import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { ScanProfile, ScheduleFrequency } from '@securityscan/contracts';

export interface IScanScheduleDocument extends Document {
  organizationId: Types.ObjectId;
  projectId: Types.ObjectId;
  targetId: Types.ObjectId;
  name: string;
  cron: string;
  frequency: ScheduleFrequency;
  profile: ScanProfile;
  enabled: boolean;
  lastRunAt?: Date;
  nextRunAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const ScanScheduleSchema = new Schema<IScanScheduleDocument>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    targetId: { type: Schema.Types.ObjectId, ref: 'Target', required: true, index: true },
    name: { type: String, required: true, trim: true },
    cron: { type: String, required: true, trim: true },
    frequency: { type: String, enum: Object.values(ScheduleFrequency), default: ScheduleFrequency.DAILY },
    profile: { type: String, enum: Object.values(ScanProfile), default: ScanProfile.WEB_STANDARD },
    enabled: { type: Boolean, default: true },
    lastRunAt: { type: Date },
    nextRunAt: { type: Date },
  },
  { timestamps: true },
);

ScanScheduleSchema.index({ organizationId: 1, enabled: 1 });

export const ScanScheduleModel = mongoose.model<IScanScheduleDocument>(
  'ScanSchedule',
  ScanScheduleSchema,
);
