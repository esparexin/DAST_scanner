import { Router } from 'express';
import dns from 'node:dns/promises';
import { TargetModel, ProjectModel, AuditLogModel } from '@securityscan/database';
import {
  CreateTargetSchema,
  UpdateTargetSchema,
  AuthorizationState,
  AuditAction,
  TargetVerificationMethod,
  SubscriptionTier,
} from '@securityscan/contracts';
import { TargetOwnershipVerifier } from '@securityscan/scope';
import { authenticate, type AuthRequest } from '../middleware/auth.js';
import { resolveTenant, type TenantRequest } from '../middleware/tenant.js';
import { validate } from '../middleware/validate.js';
import { checkTargetQuota } from '../services/quota.service.js';

export const targetRouter = Router();
targetRouter.use(authenticate);
targetRouter.use(resolveTenant as any);

targetRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.query;
    if (!projectId) {
      res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'projectId is required' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }
    const targets = await TargetModel.find({ projectId }).sort({ createdAt: -1 });
    res.json({ data: targets });
  } catch (err) {
    next(err);
  }
});

targetRouter.get('/:id', async (req: AuthRequest, res, next) => {
  try {
    const target = await TargetModel.findById(req.params['id']);
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: target.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    res.json({ data: target });
  } catch (err) {
    next(err);
  }
});

targetRouter.post('/', validate(CreateTargetSchema), async (req: AuthRequest, res, next) => {
  try {
    const project = await ProjectModel.findOne({ _id: req.body.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }

    // Enforce target limit per subscription tier
    const quotaCheck = await checkTargetQuota(
      req.userId!,
      (req as TenantRequest).orgTier ?? SubscriptionTier.FREE,
    );
    if (!quotaCheck.allowed) {
      res.status(403).json({
        error: {
          code: quotaCheck.code ?? 'QUOTA_EXCEEDED',
          message: quotaCheck.message,
          details: quotaCheck.details,
        },
      });
      return;
    }

    const target = await TargetModel.create({
      ...req.body,
      authorization: AuthorizationState.PENDING,
    });
    res.status(201).json({ data: target });
  } catch (err) {
    next(err);
  }
});

targetRouter.patch('/:id', validate(UpdateTargetSchema), async (req: AuthRequest, res, next) => {
  try {
    const target = await TargetModel.findById(req.params['id']);
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: target.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }

    // Track authorization changes
    if (req.body.authorization === AuthorizationState.AUTHORIZED && target.authorization !== AuthorizationState.AUTHORIZED) {
      req.body.authorizedAt = new Date();
      req.body.authorizedBy = req.userId;
    }

    // Handle nested scope update
    const updateData: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(req.body)) {
      if (key === 'scope' && typeof value === 'object' && value !== null) {
        for (const [sk, sv] of Object.entries(value as Record<string, unknown>)) {
          updateData[`scope.${sk}`] = sv;
        }
      } else {
        updateData[key] = value;
      }
    }

    const updated = await TargetModel.findByIdAndUpdate(
      req.params['id'],
      { $set: updateData },
      { new: true },
    );
    res.json({ data: updated });
  } catch (err) {
    next(err);
  }
});

// Initiate domain ownership verification challenge
targetRouter.post('/:id/verify/initiate', async (req: AuthRequest, res, next) => {
  try {
    const target = await TargetModel.findById(req.params['id']);
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: target.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }

    let hostname = target.scope.allowedHosts[0] || 'localhost';
    try {
      hostname = new URL(target.baseUrl).hostname;
    } catch {
      // keep fallback
    }

    const challenge = TargetOwnershipVerifier.generateChallenge(target._id.toString(), hostname);
    target.verificationChallenge = {
      token: challenge.token,
      method: req.body.method || TargetVerificationMethod.HTTP_WELL_KNOWN,
      wellKnownPath: challenge.wellKnownPath,
      expectedContent: challenge.expectedContent,
      dnsRecordName: challenge.dnsRecordName,
      dnsExpectedValue: challenge.dnsExpectedValue,
      expiresAt: challenge.expiresAt,
    };
    await target.save();

    res.json({
      data: {
        targetId: target._id,
        challenge,
      },
    });
  } catch (err) {
    next(err);
  }
});

// Check/Execute domain ownership verification challenge
targetRouter.post('/:id/verify/check', async (req: AuthRequest, res, next) => {
  try {
    const target = await TargetModel.findById(req.params['id']);
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: target.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }

    const challenge = target.verificationChallenge;
    if (!challenge) {
      res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'No active verification challenge found. Initiate verification first.' } });
      return;
    }

    if (new Date() > new Date(challenge.expiresAt)) {
      res.status(400).json({ error: { code: 'CHALLENGE_EXPIRED', message: 'Verification challenge has expired. Initiate a new challenge.' } });
      return;
    }

    const method = req.body.method || challenge.method || TargetVerificationMethod.HTTP_WELL_KNOWN;
    let verificationResult;

    if (method === TargetVerificationMethod.DNS_TXT || method === 'DNS_TXT') {
      try {
        const records = await dns.resolveTxt(challenge.dnsRecordName);
        verificationResult = TargetOwnershipVerifier.verifyDnsChallenge(records, challenge as any);
      } catch (dnsErr: any) {
        verificationResult = {
          verified: false,
          method: 'DNS_TXT' as const,
          details: `DNS lookup failed for ${challenge.dnsRecordName}: ${dnsErr?.message || 'Host not found'}`,
        };
      }
    } else {
      try {
        const checkUrl = new URL(challenge.wellKnownPath, target.baseUrl).toString();
        const response = await fetch(checkUrl, { signal: AbortSignal.timeout(5000) });
        const content = await response.text();
        verificationResult = TargetOwnershipVerifier.verifyHttpChallenge(content, challenge as any);
      } catch (httpErr: any) {
        verificationResult = {
          verified: false,
          method: 'HTTP_CHALLENGE' as const,
          details: `HTTP fetch failed at ${challenge.wellKnownPath}: ${httpErr?.message || 'Connection refused'}`,
        };
      }
    }

    if (verificationResult.verified) {
      target.authorization = AuthorizationState.AUTHORIZED;
      target.authorizedAt = new Date();
      target.authorizedBy = req.userId as any;
      await target.save();

      await AuditLogModel.create({
        action: AuditAction.TARGET_AUTHORIZED,
        actorId: req.userId,
        resourceType: 'Target',
        resourceId: target._id.toString(),
        details: { method, verificationResult },
        timestamp: new Date(),
      });
    }

    res.json({
      data: {
        verified: verificationResult.verified,
        method: verificationResult.method,
        details: verificationResult.details,
        authorization: target.authorization,
        authorizedAt: target.authorizedAt,
      },
    });
  } catch (err) {
    next(err);
  }
});
