import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { Severity, Confidence, FindingStatus, DetectionCategory } from '@securityscan/contracts';

export interface IFindingDocument extends Document {
  scanId: Types.ObjectId;
  projectId: Types.ObjectId;
  targetId: Types.ObjectId;
  ruleId: string;
  title: string;
  description: string;
  impact: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  category: DetectionCategory;
  endpoint: string;
  method: string;
  parameter?: string;
  evidenceIds: Types.ObjectId[];
  pocId?: Types.ObjectId;
  remediation: string;
  cwe: string[];
  owasp: string[];
  apiOwasp: string[];
  wstg: string[];
  asvs: string[];
  cvssVector?: string;
  cvssScore?: number;
  references: string[];
  deduplicationKey: string;
  firstDetectedAt: Date;
  lastDetectedAt: Date;
  verifiedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const FindingSchema = new Schema<IFindingDocument>(
  {
    scanId: { type: Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    targetId: { type: Schema.Types.ObjectId, ref: 'Target', required: true },
    ruleId: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    impact: { type: String, default: '' },
    severity: { type: String, enum: Object.values(Severity), required: true },
    confidence: { type: String, enum: Object.values(Confidence), required: true },
    status: { type: String, enum: Object.values(FindingStatus), default: FindingStatus.CANDIDATE },
    category: { type: String, enum: Object.values(DetectionCategory), required: true },
    endpoint: { type: String, required: true },
    method: { type: String, required: true },
    parameter: String,
    evidenceIds: [{ type: Schema.Types.ObjectId, ref: 'Evidence' }],
    pocId: { type: Schema.Types.ObjectId, ref: 'ProofOfConcept' },
    remediation: { type: String, default: '' },
    cwe: { type: [String], default: [] },
    owasp: { type: [String], default: [] },
    apiOwasp: { type: [String], default: [] },
    wstg: { type: [String], default: [] },
    asvs: { type: [String], default: [] },
    cvssVector: String,
    cvssScore: Number,
    references: { type: [String], default: [] },
    deduplicationKey: { type: String, required: true },
    firstDetectedAt: { type: Date, default: Date.now },
    lastDetectedAt: { type: Date, default: Date.now },
    verifiedAt: Date,
  },
  { timestamps: true },
);

FindingSchema.index({ scanId: 1, severity: 1 });
FindingSchema.index({ projectId: 1, deduplicationKey: 1 });
FindingSchema.index({ ruleId: 1 });

export const FindingModel = mongoose.model<IFindingDocument>('Finding', FindingSchema);
