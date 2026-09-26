import { WebhookEvent, WebhookFormat } from '../enums.js';

export interface IWebhookSubscription {
  id: string;
  organizationId: string;
  name: string;
  url: string;
  secret: string;
  events: WebhookEvent[];
  format: WebhookFormat;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ICreateWebhookInput {
  name: string;
  url: string;
  secret?: string;
  events: WebhookEvent[];
  format?: WebhookFormat;
  enabled?: boolean;
}

export interface IWebhookPayload {
  event: WebhookEvent;
  timestamp: string;
  organizationId: string;
  scanId?: string;
  targetUrl?: string;
  data: Record<string, unknown>;
}
