import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  WebhookEvent,
  WebhookFormat,
  OrgRole,
  type IWebhookPayload,
} from '@securityscan/contracts';
import {
  WebhookSubscriptionModel,
} from '@securityscan/database';
import {
  createWebhookSignature,
  verifyWebhookSignature,
  formatWebhookPayload,
  dispatchWebhook,
  dispatchTenantEvent,
} from '../services/webhook.service.js';
import { requireOrgRole, type TenantRequest } from '../middleware/tenant.js';

vi.mock('@securityscan/database', () => ({
  WebhookSubscriptionModel: {
    find: vi.fn(),
    findOne: vi.fn(),
    findById: vi.fn(),
    create: vi.fn(),
    findOneAndDelete: vi.fn(),
  },
}));

describe('Webhook & Alert Notification Dispatcher System', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('1. Cryptographic Signature & Verification', () => {
    it('generates consistent HMAC-SHA256 signature for payload', () => {
      const secret = 'whsec_test_secret_key_123456789';
      const payload = JSON.stringify({ event: 'SCAN_COMPLETED', scanId: 'scan-123' });

      const sig1 = createWebhookSignature(secret, payload);
      const sig2 = createWebhookSignature(secret, payload);

      expect(sig1).toBe(sig2);
      expect(sig1).toHaveLength(64); // SHA-256 hex is 64 chars
    });

    it('verifies valid signatures with timing-safe comparison', () => {
      const secret = 'whsec_test_secret_key_123456789';
      const payload = JSON.stringify({ event: 'SCAN_COMPLETED', scanId: 'scan-123' });
      const signature = createWebhookSignature(secret, payload);

      expect(verifyWebhookSignature(secret, payload, signature)).toBe(true);
      expect(verifyWebhookSignature(secret, payload, `sha256=${signature}`)).toBe(true);
    });

    it('rejects invalid or tampered signatures', () => {
      const secret = 'whsec_test_secret_key_123456789';
      const payload = JSON.stringify({ event: 'SCAN_COMPLETED', scanId: 'scan-123' });
      const tamperedPayload = JSON.stringify({ event: 'SCAN_COMPLETED', scanId: 'scan-999' });

      const signature = createWebhookSignature(secret, payload);

      expect(verifyWebhookSignature(secret, tamperedPayload, signature)).toBe(false);
      expect(verifyWebhookSignature('wrong_secret', payload, signature)).toBe(false);
      expect(verifyWebhookSignature(secret, payload, 'invalid_hex')).toBe(false);
    });
  });

  describe('2. Multi-Format Payload Transformers', () => {
    const testPayload: IWebhookPayload = {
      event: WebhookEvent.SCAN_COMPLETED,
      timestamp: '2026-09-26T08:00:00.000Z',
      organizationId: 'org-100',
      scanId: 'scan-abc-1',
      targetUrl: 'https://app.example.com',
      data: {
        totalFindings: 3,
        critical: 1,
        high: 2,
      },
    };

    it('formats payload for GENERIC webhooks', () => {
      const { body, contentType } = formatWebhookPayload(testPayload, WebhookFormat.GENERIC);
      expect(contentType).toBe('application/json');
      const parsed = JSON.parse(body);
      expect(parsed.event).toBe(WebhookEvent.SCAN_COMPLETED);
      expect(parsed.scanId).toBe('scan-abc-1');
      expect(parsed.data.totalFindings).toBe(3);
    });

    it('formats payload for SLACK webhooks with Block Kit structure', () => {
      const { body, contentType } = formatWebhookPayload(testPayload, WebhookFormat.SLACK);
      expect(contentType).toBe('application/json');
      const parsed = JSON.parse(body);
      expect(parsed.text).toContain('SecurityScan Alert');
      expect(parsed.blocks).toBeDefined();
      expect(parsed.blocks[0].type).toBe('header');
      expect(parsed.blocks[1].fields).toBeDefined();
    });

    it('formats payload for DISCORD webhooks with Rich Embeds and alert colors', () => {
      const { body, contentType } = formatWebhookPayload(testPayload, WebhookFormat.DISCORD);
      expect(contentType).toBe('application/json');
      const parsed = JSON.parse(body);
      expect(parsed.embeds).toBeDefined();
      expect(parsed.embeds[0].title).toContain('SecurityScan: SCAN COMPLETED');
      expect(parsed.embeds[0].color).toBe(0x10b981); // Green for completed

      const criticalPayload: IWebhookPayload = {
        ...testPayload,
        event: WebhookEvent.FINDING_CRITICAL,
      };
      const criticalDiscord = formatWebhookPayload(criticalPayload, WebhookFormat.DISCORD);
      const criticalParsed = JSON.parse(criticalDiscord.body);
      expect(criticalParsed.embeds[0].color).toBe(0xe02424); // Red for critical alert
    });
  });

  describe('3. Dispatcher Execution & Network Handling', () => {
    const originalFetch = global.fetch;

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it('successfully dispatches HTTP POST with custom headers', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
      });
      global.fetch = mockFetch;

      const sub = {
        url: 'https://hooks.example.com/alerts',
        secret: 'whsec_key_123',
        format: WebhookFormat.GENERIC,
      };
      const payload: IWebhookPayload = {
        event: WebhookEvent.SCAN_COMPLETED,
        timestamp: '2026-09-26T08:00:00.000Z',
        organizationId: 'org-1',
        data: { status: 'OK' },
      };

      const result = await dispatchWebhook(sub, payload);
      expect(result.success).toBe(true);
      expect(result.statusCode).toBe(200);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://hooks.example.com/alerts',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-SecurityScan-Event': 'SCAN_COMPLETED',
            'X-SecurityScan-Signature': expect.stringMatching(/^sha256=[a-f0-9]{64}$/),
            'X-SecurityScan-Delivery': expect.any(String),
          }),
        }),
      );
    });

    it('handles remote HTTP errors cleanly', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 502,
      });

      const sub = { url: 'https://hooks.example.com/bad', secret: 'whsec_key_123' };
      const payload: IWebhookPayload = {
        event: WebhookEvent.SCAN_FAILED,
        timestamp: '2026-09-26T08:00:00.000Z',
        organizationId: 'org-1',
        data: {},
      };

      const result = await dispatchWebhook(sub, payload);
      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(502);
      expect(result.error).toContain('status 502');
    });

    it('handles dispatch timeout gracefully', async () => {
      global.fetch = vi.fn().mockImplementation(() => {
        const error: any = new Error('The operation was aborted');
        error.name = 'AbortError';
        return Promise.reject(error);
      });

      const sub = { url: 'https://slow-server.local', secret: 'whsec_key_123' };
      const payload: IWebhookPayload = {
        event: WebhookEvent.SCAN_COMPLETED,
        timestamp: '2026-09-26T08:00:00.000Z',
        organizationId: 'org-1',
        data: {},
      };

      const result = await dispatchWebhook(sub, payload, { timeoutMs: 100 });
      expect(result.success).toBe(false);
      expect(result.error).toContain('timed out');
    });
  });

  describe('4. Tenant Multi-Webhook Broadcast (dispatchTenantEvent)', () => {
    it('dispatches events only to active subscriptions registered for the event', async () => {
      const mockSubs = [
        {
          _id: 'sub-1',
          url: 'https://slack.example.com',
          secret: 'whsec_1',
          format: WebhookFormat.SLACK,
        },
        {
          _id: 'sub-2',
          url: 'https://discord.example.com',
          secret: 'whsec_2',
          format: WebhookFormat.DISCORD,
        },
      ];

      (WebhookSubscriptionModel.find as any).mockResolvedValue(mockSubs);

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
      });

      const results = await dispatchTenantEvent('org-abc', WebhookEvent.SCAN_COMPLETED, {
        scanId: 'scan-broadcast-1',
        data: { message: 'All done' },
      });

      expect(WebhookSubscriptionModel.find).toHaveBeenCalledWith({
        organizationId: 'org-abc',
        enabled: true,
        events: WebhookEvent.SCAN_COMPLETED,
      });
      expect(results).toHaveLength(2);
      expect(results[0]?.success).toBe(true);
      expect(results[1]?.success).toBe(true);
    });

    it('returns empty array when no matching webhooks exist', async () => {
      (WebhookSubscriptionModel.find as any).mockResolvedValue([]);

      const results = await dispatchTenantEvent('org-empty', WebhookEvent.FINDING_CRITICAL, {
        data: {},
      });
      expect(results).toEqual([]);
    });
  });

  describe('5. RBAC Authorization & Security Isolation', () => {
    it('blocks VIEWER role from accessing privileged webhook configuration', () => {
      const rbacGate = requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]);
      const req: Partial<TenantRequest> = {
        orgRole: OrgRole.VIEWER,
      };
      const res: any = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      rbacGate(req as any, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({ code: 'FORBIDDEN' }),
        }),
      );
    });

    it('permits ORG_ADMIN and SECURITY_LEAD to pass RBAC gate', () => {
      const rbacGate = requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD]);
      const res: any = { status: vi.fn().mockReturnThis(), json: vi.fn() };

      const nextAdmin = vi.fn();
      rbacGate({ orgRole: OrgRole.ORG_ADMIN } as any, res, nextAdmin);
      expect(nextAdmin).toHaveBeenCalledTimes(1);

      const nextLead = vi.fn();
      rbacGate({ orgRole: OrgRole.SECURITY_LEAD } as any, res, nextLead);
      expect(nextLead).toHaveBeenCalledTimes(1);
    });
  });
});
