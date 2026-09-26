import {
  SCAN_EVENTS_CHANNEL,
  createRedisClient,
  formatScanProgressEvent,
  dispatchWebhook,
} from '@securityscan/scanner-core';
import type { ScanStatus, WebhookEvent } from '@securityscan/contracts';
import {
  ScanModel,
  TargetModel,
  ProjectModel,
  MembershipModel,
  WebhookSubscriptionModel,
} from '@securityscan/database';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('scan-events');

let redisPublisher: ReturnType<typeof createRedisClient> | null = null;

function getPublisher() {
  if (!redisPublisher) {
    redisPublisher = createRedisClient();
    redisPublisher.connect().catch((err: unknown) => {
      logger.warn({ err }, 'Failed to connect Redis publisher for scan events');
    });
  }
  return redisPublisher;
}

export async function emitProgress(
  scanId: string,
  phase: ScanStatus,
  extra?: { message?: string; endpointsDiscovered?: number; findingsTotal?: number; findingsConfirmed?: number },
): Promise<void> {
  try {
    const pub = getPublisher();
    const event = formatScanProgressEvent(scanId, phase, extra);
    await pub.publish(SCAN_EVENTS_CHANNEL, JSON.stringify(event));
  } catch (err: unknown) {
    logger.warn({ scanId, phase, err }, 'Failed to publish scan progress event');
  }
}

export async function triggerScanWebhooks(
  scanId: string,
  event: WebhookEvent,
  data: Record<string, unknown>,
): Promise<void> {
  try {
    const scan = await ScanModel.findById(scanId);
    if (!scan) return;
    const project = await ProjectModel.findById(scan.projectId);
    if (!project) return;
    const membership = await MembershipModel.findOne({ userId: project.ownerId });
    if (!membership) return;

    const target = await TargetModel.findById(scan.targetId);
    const targetUrl = target?.baseUrl;

    const subscriptions = await WebhookSubscriptionModel.find({
      organizationId: membership.organizationId,
      enabled: true,
      events: event,
    });

    if (!subscriptions || subscriptions.length === 0) return;

    const payload = {
      event,
      timestamp: new Date().toISOString(),
      organizationId: membership.organizationId.toString(),
      scanId,
      targetUrl,
      data,
    };

    await Promise.allSettled(
      subscriptions.map((sub) =>
        dispatchWebhook(
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          { url: sub.url, secret: sub.secret, format: sub.format as any },
          payload,
        ),
      ),
    );
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    logger.warn({ scanId, event, err: errorMessage }, 'Failed to trigger scan webhooks');
  }
}
