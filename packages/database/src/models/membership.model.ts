import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { OrgRole } from '@securityscan/contracts';

export interface IMembershipDocument extends Document {
  organizationId: Types.ObjectId;
  userId: Types.ObjectId;
  role: OrgRole;
  createdAt: Date;
  updatedAt: Date;
}

const MembershipSchema = new Schema<IMembershipDocument>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    role: {
      type: String,
      enum: Object.values(OrgRole),
      default: OrgRole.VIEWER,
    },
  },
  { timestamps: true },
);

MembershipSchema.index({ organizationId: 1, userId: 1 }, { unique: true });

export const MembershipModel = mongoose.model<IMembershipDocument>('Membership', MembershipSchema);
