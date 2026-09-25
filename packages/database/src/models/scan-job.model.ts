import mongoose, { Schema, type Document, type Types } from 'mongoose';

export interface IScanJobDocument extends Document {
  scanId: Types.ObjectId;
  type: string;
  status: 'pending' | 'active' | 'completed' | 'failed';
  payload: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: string;
  startedAt?: Date;
  completedAt?: Date;
  createdAt: Date;
}

const ScanJobSchema = new Schema<IScanJobDocument>(
  {
    scanId: { type: Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    type: { type: String, required: true },
    status: { type: String, enum: ['pending', 'active', 'completed', 'failed'], default: 'pending' },
    payload: { type: Schema.Types.Mixed, default: {} },
    result: Schema.Types.Mixed,
    error: String,
    startedAt: Date,
    completedAt: Date,
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

export const ScanJobModel = mongoose.model<IScanJobDocument>('ScanJob', ScanJobSchema);
