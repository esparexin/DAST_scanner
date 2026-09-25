import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { AuditAction } from '@securityscan/contracts';

export interface IAuditLogDocument extends Document {
  action: AuditAction;
  actorId: Types.ObjectId;
  actorEmail?: string;
  resourceType: string;
  resourceId: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  timestamp: Date;
}

const AuditLogSchema = new Schema<IAuditLogDocument>(
  {
    action: { type: String, enum: Object.values(AuditAction), required: true },
    actorId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    actorEmail: String,
    resourceType: { type: String, required: true },
    resourceId: { type: String, required: true },
    details: Schema.Types.Mixed,
    ipAddress: String,
    timestamp: { type: Date, default: Date.now },
  },
  { timestamps: false },
);

AuditLogSchema.index({ timestamp: -1 });
AuditLogSchema.index({ actorId: 1, timestamp: -1 });
AuditLogSchema.index({ resourceType: 1, resourceId: 1 });

export const AuditLogModel = mongoose.model<IAuditLogDocument>('AuditLog', AuditLogSchema);
