import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { ApiSchemaFormat } from '@securityscan/contracts';

export interface IApiSchemaDocument extends Document {
  apiId: Types.ObjectId;
  projectId: Types.ObjectId;
  format: ApiSchemaFormat;
  version?: string;
  content: string;
  parsed: boolean;
  valid: boolean;
  validationErrors?: string[];
  endpointCount?: number;
  importedAt: Date;
  createdAt: Date;
}

const ApiSchemaSchema = new Schema<IApiSchemaDocument>(
  {
    apiId: { type: Schema.Types.ObjectId, ref: 'Api', required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true },
    format: { type: String, enum: Object.values(ApiSchemaFormat), required: true },
    version: String,
    content: { type: String, required: true },
    parsed: { type: Boolean, default: false },
    valid: { type: Boolean, default: false },
    validationErrors: [String],
    endpointCount: Number,
    importedAt: { type: Date, default: Date.now },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

export const ApiSchemaModel = mongoose.model<IApiSchemaDocument>('ApiSchema', ApiSchemaSchema);
