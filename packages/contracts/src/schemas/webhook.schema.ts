import { z } from 'zod';
import { WebhookEvent, WebhookFormat } from '../enums.js';

export const CreateWebhookSchema = z.object({
  name: z.string().min(1).max(200).trim(),
  url: z
    .string()
    .url()
    .refine((u) => ['http:', 'https:'].includes(new URL(u).protocol), {
      message: 'Webhook URL must use HTTP or HTTPS',
    }),
  events: z
    .array(z.nativeEnum(WebhookEvent))
    .min(1, 'At least one event type is required'),
  format: z.nativeEnum(WebhookFormat).optional().default(WebhookFormat.GENERIC),
  enabled: z.boolean().optional().default(true),
  /** Optional custom secret — generated server-side if omitted */
  secret: z.string().min(16).max(512).optional(),
});

export type CreateWebhookInput = z.infer<typeof CreateWebhookSchema>;

export const UpdateWebhookSchema = z.object({
  name: z.string().min(1).max(200).trim().optional(),
  url: z
    .string()
    .url()
    .refine((u) => ['http:', 'https:'].includes(new URL(u).protocol), {
      message: 'Webhook URL must use HTTP or HTTPS',
    })
    .optional(),
  events: z.array(z.nativeEnum(WebhookEvent)).min(1).optional(),
  format: z.nativeEnum(WebhookFormat).optional(),
  enabled: z.boolean().optional(),
});

export type UpdateWebhookInput = z.infer<typeof UpdateWebhookSchema>;
