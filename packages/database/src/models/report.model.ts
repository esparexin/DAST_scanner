import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { ReportFormat } from '@securityscan/contracts';

export interface IReportDocument extends Document {
  scanId: Types.ObjectId;
  projectId: Types.ObjectId;
  targetId: Types.ObjectId;
  format: ReportFormat;
  title: string;
  generatedAt: Date;
  scope: {
    targetUrl: string;
    allowedHosts: string[];
    excludedHosts: string[];
    scanProfile: string;
    startedAt?: Date;
    completedAt?: Date;
  };
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    confirmedCount: number;
    endpointsScanned: number;
    requestsMade: number;
  };
  content?: string;
  filePath?: string;
  storageKey?: string;
  storageUrl?: string;
  createdAt: Date;
}

const ReportSchema = new Schema<IReportDocument>(
  {
    scanId: { type: Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true },
    targetId: { type: Schema.Types.ObjectId, ref: 'Target', required: true },
    format: { type: String, enum: Object.values(ReportFormat), required: true },
    title: { type: String, required: true },
    generatedAt: { type: Date, default: Date.now },
    scope: {
      targetUrl: String,
      allowedHosts: [String],
      excludedHosts: [String],
      scanProfile: String,
      startedAt: Date,
      completedAt: Date,
    },
    summary: {
      totalFindings: { type: Number, default: 0 },
      criticalCount: { type: Number, default: 0 },
      highCount: { type: Number, default: 0 },
      mediumCount: { type: Number, default: 0 },
      lowCount: { type: Number, default: 0 },
      infoCount: { type: Number, default: 0 },
      confirmedCount: { type: Number, default: 0 },
      endpointsScanned: { type: Number, default: 0 },
      requestsMade: { type: Number, default: 0 },
    },
    content: String,
    filePath: String,
    storageKey: String,
    storageUrl: String,
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

export const ReportModel = mongoose.model<IReportDocument>('Report', ReportSchema);
