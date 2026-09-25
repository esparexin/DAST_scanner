import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { HttpMethod } from '@securityscan/contracts';

export interface IEndpointDocument extends Document {
  scanId: Types.ObjectId;
  targetId: Types.ObjectId;
  projectId: Types.ObjectId;
  method: HttpMethod;
  url: string;
  path: string;
  parameters: Array<{
    name: string;
    location: string;
    type?: string;
    required?: boolean;
    example?: string;
  }>;
  headers: Record<string, string>;
  requestContentType?: string;
  responseContentType?: string;
  statusCode?: number;
  requiresAuth: boolean;
  discoverySource: string;
  apiId?: Types.ObjectId;
  schemaOperationId?: string;
  createdAt: Date;
}

const EndpointSchema = new Schema<IEndpointDocument>(
  {
    scanId: { type: Schema.Types.ObjectId, ref: 'Scan', required: true, index: true },
    targetId: { type: Schema.Types.ObjectId, ref: 'Target', required: true },
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true },
    method: { type: String, enum: Object.values(HttpMethod), required: true },
    url: { type: String, required: true },
    path: { type: String, required: true },
    parameters: [
      {
        name: String,
        location: String,
        type: String,
        required: Boolean,
        example: String,
      },
    ],
    headers: { type: Schema.Types.Mixed, default: {} },
    requestContentType: String,
    responseContentType: String,
    statusCode: Number,
    requiresAuth: { type: Boolean, default: false },
    discoverySource: { type: String, required: true },
    apiId: { type: Schema.Types.ObjectId, ref: 'Api' },
    schemaOperationId: String,
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

EndpointSchema.index({ scanId: 1, path: 1, method: 1 });

export const EndpointModel = mongoose.model<IEndpointDocument>('Endpoint', EndpointSchema);
