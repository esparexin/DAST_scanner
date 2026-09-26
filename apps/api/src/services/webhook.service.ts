import { WebhookEvent, type IWebhookPayload } from '@securityscan/contracts';
import { WebhookSubscriptionModel } from '@securityscan/database';
import {
  createWebhookSignature,
  verifyWebhookSignature,
  formatWebhookPayload,
  dispatchWebhook,
} from '@securityscan/scanner-core';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('webhook-service');

export {
  createWebhookSignature,
  verifyWebhookSignature,
  formatWebhookPayload,
  dispatchWebhook,
};

export async function dispatchTenantEvent(
  organizationId: string,
  event: WebhookEvent,
  payloadData: { scanId?: string; targetUrl?: string; data: Record<string, unknown> },
): Promise<Array<{ subscriptionId: string; success: boolean; error?: string }>> {
  try {
    const subscriptions = await WebhookSubscriptionModel.find({
      organizationId,
      enabled: true,
      events: event,
    });

    if (!subscriptions || subscriptions.length === 0) {
      return [];
    }

    const payload: IWebhookPayload = {
      event,
      timestamp: new Date().toISOString(),
      organizationId,
      scanId: payloadData.scanId,
      targetUrl: payloadData.targetUrl,
      data: payloadData.data,
    };

    const results = await Promise.allSettled(
      subscriptions.map(async (sub) => {
        const res = await dispatchWebhook(
          {
            url: sub.url,
            secret: sub.secret,
            format: sub.format,
          },
          payload,
        );
        return {
          subscriptionId: sub._id.toString(),
          success: res.success,
          error: res.error,
        };
      }),
    );

    return results.map((r, i) => {
      if (r.status === 'fulfilled') {
        return r.value;
      }
      return {
        subscriptionId: subscriptions[i]!._id.toString(),
        success: false,
        error: r.reason?.message ?? 'Failed to dispatch webhook',
      };
    });
  } catch (err: any) {
    logger.error({ organizationId, event, err: err?.message }, 'Error dispatching tenant webhooks');
    return [];
  }
}
