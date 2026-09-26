import crypto from 'node:crypto';
import { WebhookEvent, WebhookFormat, type IWebhookPayload } from '@securityscan/contracts';

export function createWebhookSignature(secret: string, payload: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

export function verifyWebhookSignature(secret: string, payload: string, signature: string): boolean {
  try {
    const expected = createWebhookSignature(secret, payload);
    const expectedBuf = Buffer.from(expected, 'hex');
    const actualBuf = Buffer.from(signature.replace(/^sha256=/, ''), 'hex');
    if (expectedBuf.length !== actualBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, actualBuf);
  } catch {
    return false;
  }
}

export function formatWebhookPayload(
  payload: IWebhookPayload,
  format: WebhookFormat,
): { body: string; contentType: string } {
  if (format === WebhookFormat.SLACK) {
    const eventTitle = `🛡️ SecurityScan Alert: ${payload.event.replace('_', ' ')}`;
    const fields = [
      { type: 'mrkdwn', text: `*Event:*\n\`${payload.event}\`` },
      { type: 'mrkdwn', text: `*Time:*\n${payload.timestamp}` },
    ];
    if (payload.scanId) {
      fields.push({ type: 'mrkdwn', text: `*Scan ID:*\n\`${payload.scanId}\`` });
    }
    if (payload.targetUrl) {
      fields.push({ type: 'mrkdwn', text: `*Target URL:*\n${payload.targetUrl}` });
    }

    const slackBody = {
      text: `${eventTitle} - ${payload.targetUrl ?? payload.scanId ?? 'Notification'}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: eventTitle, emoji: true },
        },
        {
          type: 'section',
          fields,
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `\`\`\`json\n${JSON.stringify(payload.data, null, 2)}\n\`\`\``,
          },
        },
      ],
    };
    return { body: JSON.stringify(slackBody), contentType: 'application/json' };
  }

  if (format === WebhookFormat.DISCORD) {
    const isCritical = payload.event === WebhookEvent.FINDING_CRITICAL || payload.event === WebhookEvent.SCAN_FAILED;
    const color = isCritical ? 0xe02424 : 0x10b981; // Red or Green

    const fields = [
      { name: 'Event', value: `\`${payload.event}\``, inline: true },
      { name: 'Timestamp', value: payload.timestamp, inline: true },
    ];
    if (payload.scanId) {
      fields.push({ name: 'Scan ID', value: `\`${payload.scanId}\``, inline: true });
    }
    if (payload.targetUrl) {
      fields.push({ name: 'Target URL', value: payload.targetUrl, inline: false });
    }

    const discordBody = {
      embeds: [
        {
          title: `🛡️ SecurityScan: ${payload.event.replace('_', ' ')}`,
          color,
          fields,
          description: `\`\`\`json\n${JSON.stringify(payload.data, null, 2)}\n\`\`\``,
          footer: { text: 'SecurityScan DAST Platform' },
          timestamp: payload.timestamp,
        },
      ],
    };
    return { body: JSON.stringify(discordBody), contentType: 'application/json' };
  }

  return {
    body: JSON.stringify(payload),
    contentType: 'application/json',
  };
}

export async function dispatchWebhook(
  subscription: { url: string; secret: string; format?: WebhookFormat },
  payload: IWebhookPayload,
  options?: { timeoutMs?: number },
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
  const timeoutMs = options?.timeoutMs ?? 5000;
  const format = subscription.format ?? WebhookFormat.GENERIC;
  const { body, contentType } = formatWebhookPayload(payload, format);
  const signature = createWebhookSignature(subscription.secret, body);
  const deliveryId = crypto.randomUUID();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(subscription.url, {
      method: 'POST',
      headers: {
        'Content-Type': contentType,
        'User-Agent': 'SecurityScan-Webhook-Dispatcher/1.0',
        'X-SecurityScan-Signature': `sha256=${signature}`,
        'X-SecurityScan-Event': payload.event,
        'X-SecurityScan-Delivery': deliveryId,
      },
      body,
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (res.ok) {
      return { success: true, statusCode: res.status };
    } else {
      return {
        success: false,
        statusCode: res.status,
        error: `Webhook recipient responded with status ${res.status}`,
      };
    }
  } catch (err: any) {
    clearTimeout(timer);
    const errorMsg =
      err?.name === 'AbortError'
        ? `Webhook request timed out after ${timeoutMs}ms`
        : err?.message ?? 'Network error';
    return { success: false, error: errorMsg };
  }
}
