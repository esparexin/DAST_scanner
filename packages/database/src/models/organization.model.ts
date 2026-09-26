import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { SubscriptionTier } from '@securityscan/contracts';

export interface IOrganizationDocument extends Document {
  name: string;
  slug: string;
  tier: SubscriptionTier;
  ownerId: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

const OrganizationSchema = new Schema<IOrganizationDocument>(
  {
    name: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
    tier: {
      type: String,
      enum: Object.values(SubscriptionTier),
      default: SubscriptionTier.FREE,
    },
    ownerId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  },
  { timestamps: true },
);

export const OrganizationModel = mongoose.model<IOrganizationDocument>('Organization', OrganizationSchema);
