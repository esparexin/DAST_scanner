import { Router } from 'express';
import crypto from 'node:crypto';
import { WebhookSubscriptionModel } from '@securityscan/database';
import { OrgRole, WebhookEvent, WebhookFormat, CreateWebhookSchema } from '@securityscan/contracts';
import { authenticate } from '../middleware/auth.js';
import { resolveTenant, requireOrgRole, type TenantRequest } from '../middleware/tenant.js';
import { validate } from '../middleware/validate.js';
import { dispatchWebhook } from '../services/webhook.service.js';

export const webhookRouter = Router();
webhookRouter.use(authenticate);
webhookRouter.use(resolveTenant);

// List tenant webhooks
webhookRouter.get('/', async (req: TenantRequest, res, next) => {
  try {
    const webhooks = await WebhookSubscriptionModel.find({
      organizationId: req.organizationId,
    }).sort({ createdAt: -1 });

    const safeWebhooks = webhooks.map((w) => ({
      id: w._id.toString(),
      organizationId: w.organizationId.toString(),
      name: w.name,
      url: w.url,
      events: w.events,
      format: w.format,
      enabled: w.enabled,
      secretPrefix: `${w.secret.slice(0, 8)}...`,
      createdAt: w.createdAt,
      updatedAt: w.updatedAt,
    }));

    res.json({ data: safeWebhooks });
  } catch (err) {
    next(err);
  }
});

// Create tenant webhook (restricted to ORG_ADMIN and SECURITY_LEAD)
webhookRouter.post(
  '/',
  requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]),
  validate(CreateWebhookSchema),
  async (req: TenantRequest, res, next) => {
    try {
      const { name, url, events, format, enabled, secret } = req.body as import('@securityscan/contracts').CreateWebhookInput;

      const generatedSecret =
        secret && secret.length >= 16
          ? secret
          : `whsec_${crypto.randomBytes(24).toString('hex')}`;

      const created = await WebhookSubscriptionModel.create({
        organizationId: req.organizationId,
        name,
        url,
        secret: generatedSecret,
        events,
        format: format ?? WebhookFormat.GENERIC,
        enabled: enabled ?? true,
      });

      res.status(201).json({
        data: {
          id: created._id.toString(),
          organizationId: created.organizationId.toString(),
          name: created.name,
          url: created.url,
          events: created.events,
          format: created.format,
          enabled: created.enabled,
          secret: generatedSecret,
          createdAt: created.createdAt,
          updatedAt: created.updatedAt,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

// Delete webhook (restricted to ORG_ADMIN and SECURITY_LEAD)
webhookRouter.delete(
  '/:id',
  requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]),
  async (req: TenantRequest, res, next) => {
    try {
      const webhook = await WebhookSubscriptionModel.findOneAndDelete({
        _id: req.params['id'],
        organizationId: req.organizationId,
      });

      if (!webhook) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Webhook subscription not found' } });
        return;
      }

      res.json({ data: { message: 'Webhook subscription deleted successfully' } });
    } catch (err) {
      next(err);
    }
  },
);

// Test webhook endpoint (ping test)
webhookRouter.post(
  '/:id/test',
  requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]),
  async (req: TenantRequest, res, next) => {
    try {
      const webhook = await WebhookSubscriptionModel.findOne({
        _id: req.params['id'],
        organizationId: req.organizationId,
      });

      if (!webhook) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Webhook subscription not found' } });
        return;
      }

      const testPayload = {
        event: WebhookEvent.SCAN_COMPLETED,
        timestamp: new Date().toISOString(),
        organizationId: req.organizationId!,
        scanId: 'scan-test-ping',
        targetUrl: 'https://securityscan-ping.local',
        data: {
          message: 'Test ping notification from SecurityScan platform',
          status: 'TEST_SUCCESS',
          totalFindings: 0,
        },
      };

      const result = await dispatchWebhook(
        {
          url: webhook.url,
          secret: webhook.secret,
          format: webhook.format,
        },
        testPayload,
        { timeoutMs: 5000 },
      );

      res.json({ data: result });
    } catch (err) {
      next(err);
    }
  },
);
