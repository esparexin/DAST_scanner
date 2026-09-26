import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { WebhookEvent, WebhookFormat } from '@securityscan/contracts';

export interface IWebhookSubscriptionDocument extends Document {
  organizationId: Types.ObjectId;
  name: string;
  url: string;
  secret: string;
  events: WebhookEvent[];
  format: WebhookFormat;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const WebhookSubscriptionSchema = new Schema<IWebhookSubscriptionDocument>(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    name: { type: String, required: true, trim: true },
    url: { type: String, required: true, trim: true },
    secret: { type: String, required: true },
    events: [{ type: String, enum: Object.values(WebhookEvent) }],
    format: { type: String, enum: Object.values(WebhookFormat), default: WebhookFormat.GENERIC },
    enabled: { type: Boolean, default: true },
  },
  { timestamps: true },
);

WebhookSubscriptionSchema.index({ organizationId: 1, enabled: 1 });

export const WebhookSubscriptionModel = mongoose.model<IWebhookSubscriptionDocument>(
  'WebhookSubscription',
  WebhookSubscriptionSchema,
);
