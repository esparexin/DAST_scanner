import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { ApiType } from '@securityscan/contracts';

export interface IApiDocument extends Document {
  projectId: Types.ObjectId;
  targetId: Types.ObjectId;
  name: string;
  type: ApiType;
  baseUrl: string;
  version?: string;
  description?: string;
  schemaId?: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

const ApiSchema = new Schema<IApiDocument>(
  {
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    targetId: { type: Schema.Types.ObjectId, ref: 'Target', required: true },
    name: { type: String, required: true, trim: true },
    type: { type: String, enum: Object.values(ApiType), required: true },
    baseUrl: { type: String, required: true },
    version: String,
    description: String,
    schemaId: { type: Schema.Types.ObjectId, ref: 'ApiSchema' },
  },
  { timestamps: true },
);

export const ApiModel = mongoose.model<IApiDocument>('Api', ApiSchema);
