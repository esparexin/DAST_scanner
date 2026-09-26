import mongoose, { Schema, type Document, type Types } from 'mongoose';

export interface IEvidenceDocument extends Document {
  findingId: Types.ObjectId;
  scanId: Types.ObjectId;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    statusCode: number;
    headers: Record<string, string>;
    body?: string;
    responseTime: number;
  };
  endpoint: string;
  parameter?: string;
  authContext: string;
  comparisonResults?: Array<{
    label: string;
    expected: string;
    actual: string;
    match: boolean;
  }>;
  timestamp: Date;
  relevantHeaders: Record<string, string>;
  relevantResponseData: string;
  storageKey?: string;
  storageUrl?: string;
  createdAt: Date;
}

const EvidenceSchema = new Schema<IEvidenceDocument>(
  {
    findingId: { type: Schema.Types.ObjectId, ref: 'Finding', required: true, index: true },
    scanId: { type: Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    request: {
      method: { type: String, required: true },
      url: { type: String, required: true },
      headers: { type: Schema.Types.Mixed, default: {} },
      body: String,
    },
    response: {
      statusCode: { type: Number, required: true },
      headers: { type: Schema.Types.Mixed, default: {} },
      body: String,
      responseTime: { type: Number, default: 0 },
    },
    endpoint: { type: String, required: true },
    parameter: String,
    authContext: { type: String, default: 'anonymous' },
    comparisonResults: [
      {
        label: String,
        expected: String,
        actual: String,
        match: Boolean,
      },
    ],
    timestamp: { type: Date, default: Date.now },
    relevantHeaders: { type: Schema.Types.Mixed, default: {} },
    relevantResponseData: { type: String, default: '' },
    storageKey: String,
    storageUrl: String,
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

export const EvidenceModel = mongoose.model<IEvidenceDocument>('Evidence', EvidenceSchema);
