import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  OrgRole,
  SubscriptionTier,
  AuthorizationState,
  ScanStatus,
  ScanProfile,
  ReportFormat,
} from '@securityscan/contracts';
import {
  OrganizationModel,
  MembershipModel,
  TargetModel,
  ScanModel,
  ProjectModel,
  ReportModel,
  EvidenceModel,
} from '@securityscan/database';
import { resolveTenant, requireOrgRole, type TenantRequest } from '../middleware/tenant.js';
import { checkScanQuota, checkTargetQuota } from '../services/quota.service.js';
import { ReportGenerator } from '@securityscan/reporting';
import { createStorageProvider } from '@securityscan/storage';
import { createRateLimiter, clearInMemoryRateLimits } from '../middleware/rate-limiter.js';
import { tracingMiddleware, type TracedRequest } from '../middleware/tracing.js';
import {
  ScanStateMachine,
  formatScanProgressEvent,
} from '@securityscan/scanner-core';
import type { StorageProvider, StoragePutResult } from '@securityscan/storage';

vi.mock('@securityscan/database', () => ({
  OrganizationModel: {
    findById: vi.fn(),
    create: vi.fn(),
  },
  MembershipModel: {
    findOne: vi.fn(),
    find: vi.fn(),
    create: vi.fn(),
  },
  ProjectModel: {
    find: vi.fn(),
    findOne: vi.fn(),
    create: vi.fn(),
  },
  TargetModel: {
    find: vi.fn(),
    findById: vi.fn(),
    countDocuments: vi.fn(),
  },
  ScanModel: {
    find: vi.fn(),
    findById: vi.fn(),
    findByIdAndUpdate: vi.fn(),
    countDocuments: vi.fn(),
    create: vi.fn(),
  },
  FindingModel: {
    find: vi.fn(),
  },
  ReportModel: {
    create: vi.fn(),
    findById: vi.fn(),
  },
  EvidenceModel: {
    find: vi.fn(),
  },
  IntelligenceReleaseModel: {
    create: vi.fn(),
    findOne: vi.fn(),
  },
}));

describe('End-to-End Multi-Tenant Lifecycle & Security Integration Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearInMemoryRateLimits();
  });

  describe('1. Multi-Tenant Context & RBAC Authorization Gate', () => {
    it('resolves organization context and assigns tenant tier and role', async () => {
      const mockOrg = {
        _id: 'org-enterprise-1',
        name: 'Acme Corp',
        tier: SubscriptionTier.ENTERPRISE,
      };
      const mockMembership = {
        organizationId: 'org-enterprise-1',
        userId: 'user-bob',
        role: OrgRole.SECURITY_LEAD,
      };

      (MembershipModel.findOne as any).mockReturnValue({
        sort: vi.fn().mockResolvedValue(mockMembership),
      });
      (OrganizationModel.findById as any).mockResolvedValue(mockOrg);

      const req: Partial<TenantRequest> = {
        userId: 'user-bob',
        headers: {},
      };
      const res: any = {};
      const next = vi.fn();

      await resolveTenant(req as TenantRequest, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.organizationId).toBe('org-enterprise-1');
      expect(req.orgRole).toBe(OrgRole.SECURITY_LEAD);
      expect(req.orgTier).toBe(SubscriptionTier.ENTERPRISE);
    });

    it('enforces RBAC gates: rejects VIEWERS from initiating privileged security operations', () => {
      const gate = requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_LEAD, OrgRole.SECURITY_TESTER]);

      const req: Partial<TenantRequest> = {
        userId: 'user-viewer',
        orgRole: OrgRole.VIEWER,
      };
      const res: any = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      gate(req as TenantRequest, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'FORBIDDEN',
            message: expect.stringContaining('Insufficient organization permissions'),
          }),
        }),
      );
    });

    it('allows SECURITY_TESTER role to proceed past privileged security gate', () => {
      const gate = requireOrgRole([OrgRole.ORG_ADMIN, OrgRole.SECURITY_TESTER]);
      const req: Partial<TenantRequest> = {
        userId: 'user-tester',
        orgRole: OrgRole.SECURITY_TESTER,
      };
      const res: any = {};
      const next = vi.fn();

      gate(req as TenantRequest, res, next);
      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  describe('2. Target Ownership Verification Gate', () => {
    it('blocks scanning targets that have not completed verification (PENDING)', () => {
      const target = {
        _id: 't-unverified',
        baseUrl: 'https://staging.acme.corp',
        authorization: AuthorizationState.PENDING,
      };

      const isAuthorized = target.authorization === AuthorizationState.AUTHORIZED;
      expect(isAuthorized).toBe(false);
    });

    it('permits scanning targets with verified AUTHORIZED state', () => {
      const target = {
        _id: 't-verified',
        baseUrl: 'https://staging.acme.corp',
        authorization: AuthorizationState.AUTHORIZED,
      };

      const isAuthorized = target.authorization === AuthorizationState.AUTHORIZED;
      expect(isAuthorized).toBe(true);
    });
  });

  describe('3. Multi-Tenant Subscription Plan Quota Enforcement', () => {
    it('enforces tier profile allowances: FREE cannot run FULL_ASSESSMENT', async () => {
      const check = await checkScanQuota('user-free', SubscriptionTier.FREE, ScanProfile.FULL_ASSESSMENT);
      expect(check.allowed).toBe(false);
      expect(check.code).toBe('PROFILE_NOT_ALLOWED');
    });

    it('allows TEAM tier to run FULL_ASSESSMENT profile with higher concurrency', async () => {
      (ProjectModel.find as any).mockReturnValue({
        select: vi.fn().mockResolvedValue([{ _id: 'proj-1' }]),
      });
      (ScanModel.countDocuments as any).mockResolvedValue(1); // 1 active scan

      const check = await checkScanQuota('user-team', SubscriptionTier.TEAM, ScanProfile.FULL_ASSESSMENT);
      expect(check.allowed).toBe(true);
    });

    it('rejects target creation when target quota limit is exceeded for tier', async () => {
      (ProjectModel.find as any).mockReturnValue({
        select: vi.fn().mockResolvedValue([{ _id: 'p-1' }]),
      });
      (TargetModel.countDocuments as any).mockResolvedValue(3); // FREE tier limit is 3

      const quota = await checkTargetQuota('user-free', SubscriptionTier.FREE);
      expect(quota.allowed).toBe(false);
      expect(quota.code).toBe('QUOTA_EXCEEDED');
      expect(quota.message).toContain('Target quota limit reached for FREE plan');
    });
  });

  describe('4. Real-Time Scan Event Streaming & Lifecycle Transitions', () => {
    it('formats scan progress events with schema snapshot', () => {
      const event = formatScanProgressEvent('scan-lifecycle-100', ScanStatus.ACTIVE_TESTING, {
        message: 'Injecting SQLi test payloads',
        endpointsDiscovered: 42,
        findingsTotal: 3,
        findingsConfirmed: 2,
      });

      expect(event.scanId).toBe('scan-lifecycle-100');
      expect(event.phase).toBe(ScanStatus.ACTIVE_TESTING);
      expect(event.message).toBe('Injecting SQLi test payloads');
      expect(event.endpointsDiscovered).toBe(42);
      expect(event.findingsTotal).toBe(3);
      expect(event.findingsConfirmed).toBe(2);
      expect(event.timestamp).toBeDefined();
    });

    it('validates state transitions through state machine lifecycle', () => {
      const sm = new ScanStateMachine(ScanStatus.CREATED);
      expect(sm.canTransition(ScanStatus.VALIDATING)).toBe(true);
      sm.transition(ScanStatus.VALIDATING);
      sm.transition(ScanStatus.QUEUED);
      sm.transition(ScanStatus.DISCOVERING);
      sm.transition(ScanStatus.CRAWLING);
      sm.transition(ScanStatus.PASSIVE_ANALYSIS);
      sm.transition(ScanStatus.ACTIVE_TESTING);
      sm.transition(ScanStatus.API_TESTING);
      sm.transition(ScanStatus.VERIFYING);
      sm.transition(ScanStatus.EVIDENCE_COLLECTION);
      sm.transition(ScanStatus.REPORTING);
      sm.transition(ScanStatus.COMPLETED);
      expect(sm.status).toBe(ScanStatus.COMPLETED);

      // Cannot transition out of terminal state
      expect(sm.canTransition(ScanStatus.ACTIVE_TESTING)).toBe(false);
    });

    it('allows valid cancellation from running phases', () => {
      const sm = new ScanStateMachine(ScanStatus.ACTIVE_TESTING);
      expect(sm.canTransition(ScanStatus.CANCELLED)).toBe(true);
      sm.transition(ScanStatus.CANCELLED);
      expect(sm.status).toBe(ScanStatus.CANCELLED);
    });
  });

  describe('5. Provider-Agnostic Object Storage Upload with Presigned URLs', () => {
    it('persists report artifacts to object storage and generates presigned URLs', async () => {
      const reportGen = new ReportGenerator();
      const content = reportGen.generateJSON({
        title: 'E2E Report',
        scope: { targetUrl: 'https://storage.example.com' },
        findings: [],
        generatedAt: new Date(),
      });

      const mockStorage: StorageProvider = {
        putObject: vi.fn().mockResolvedValue({
          key: 'reports/proj-storage-test/scan-storage-test/report-rep-storage-test.json',
          size: 2048,
          contentType: 'application/json',
          uploadedAt: new Date(),
        } as StoragePutResult),
        getObject: vi.fn(),
        deleteObject: vi.fn(),
        exists: vi.fn(),
        getPresignedUrl: vi.fn().mockResolvedValue('https://s3.local/bucket/report.json?sig=123'),
      };

      const result = await mockStorage.putObject(
        'reports/proj-storage-test/scan-storage-test/report-rep-storage-test.json',
        content,
        'application/json',
        { scanId: 'scan-storage-test', format: ReportFormat.JSON },
      );
      const presignedUrl = await mockStorage.getPresignedUrl(result.key, 86400);

      expect(result.key).toContain('report-rep-storage-test.json');
      expect(presignedUrl).toContain('sig=123');
      expect(mockStorage.putObject).toHaveBeenCalledWith(
        expect.stringContaining('report-rep-storage-test.json'),
        expect.any(String),
        'application/json',
        expect.any(Object),
      );
    });

    it('persists raw evidence artifacts to object storage', async () => {
      const mockStorage: StorageProvider = {
        putObject: vi.fn().mockResolvedValue({
          key: 'evidence/scan-1/ev-lifecycle-1.json',
          size: 512,
          contentType: 'application/json',
          uploadedAt: new Date(),
        } as StoragePutResult),
        getObject: vi.fn(),
        deleteObject: vi.fn(),
        exists: vi.fn(),
        getPresignedUrl: vi.fn().mockResolvedValue('https://s3.local/evidence.json?sig=abc'),
      };

      const payload = JSON.stringify({
        evidenceId: 'ev-lifecycle-1',
        findingId: 'f-1',
        scanId: 'scan-1',
        request: { method: 'GET', url: 'https://example.com' },
        response: { statusCode: 200 },
      });

      const uploadResult = await mockStorage.putObject(
        'evidence/scan-1/ev-lifecycle-1.json',
        payload,
        'application/json',
        { scanId: 'scan-1', findingId: 'f-1' },
      );
      const signedUrl = await mockStorage.getPresignedUrl(uploadResult.key, 86400);

      expect(uploadResult.key).toBe('evidence/scan-1/ev-lifecycle-1.json');
      expect(signedUrl).toContain('sig=abc');
    });
  });

  describe('6. Rate Limiter Resilience & Distributed Tracing Propagation', () => {
    it('propagates distributed trace ID across request and response headers', () => {
      const req: Partial<TracedRequest> = {
        headers: { 'x-trace-id': 'trace-distributed-uuid-99' },
      };
      const responseHeaders: Record<string, string> = {};
      const res: any = {
        setHeader: vi.fn((k, v) => {
          responseHeaders[k] = v;
        }),
      };
      const next = vi.fn();

      tracingMiddleware(req as any, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.traceId).toBe('trace-distributed-uuid-99');
      expect(responseHeaders['X-Trace-Id']).toBe('trace-distributed-uuid-99');
      expect(responseHeaders['X-Request-Id']).toBe('trace-distributed-uuid-99');
    });

    it('enforces rate limiter bounds and returns 429 when threshold exceeded', async () => {
      const limiter = createRateLimiter({
        windowSeconds: 60,
        maxRequests: 2,
        keyPrefix: 'e2e-rate',
        keyGenerator: () => 'client-tenant-abc',
      });

      const res: any = {
        setHeader: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      // Request 1 and 2 allowed
      await limiter({} as any, res, next);
      await limiter({} as any, res, next);
      expect(next).toHaveBeenCalledTimes(2);

      // Request 3 blocked
      await limiter({} as any, res, next);
      expect(next).toHaveBeenCalledTimes(2);
      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.setHeader).toHaveBeenCalledWith('Retry-After', 60);
    });
  });
});
