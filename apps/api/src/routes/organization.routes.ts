import { Router } from 'express';
import { OrganizationModel, MembershipModel } from '@securityscan/database';
import { OrgRole, SubscriptionTier } from '@securityscan/contracts';
import { authenticate } from '../middleware/auth.js';
import { resolveTenant, requireOrgRole, type TenantRequest } from '../middleware/tenant.js';

export const organizationRouter = Router();
organizationRouter.use(authenticate);

// List all organizations the user belongs to
organizationRouter.get('/', async (req: TenantRequest, res, next) => {
  try {
    const memberships = await MembershipModel.find({ userId: req.userId }).populate('organizationId');
    const orgs = memberships.map((m) => ({
      organization: m.organizationId,
      role: m.role,
    }));
    res.json({ data: orgs });
  } catch (err) {
    next(err);
  }
});

// Get current active organization
organizationRouter.get('/current', resolveTenant, async (req: TenantRequest, res, next) => {
  try {
    const org = await OrganizationModel.findById(req.organizationId);
    if (!org) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Organization not found' } });
      return;
    }
    res.json({
      data: {
        organization: org,
        role: req.orgRole,
      },
    });
  } catch (err) {
    next(err);
  }
});

// Create new organization
organizationRouter.post('/', async (req: TenantRequest, res, next) => {
  try {
    const { name, slug } = req.body;
    if (!name || typeof name !== 'string') {
      res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Organization name is required' } });
      return;
    }

    const orgSlug = (slug || name.toLowerCase().replace(/[^a-z0-9]/g, '-')) + '-' + Date.now().toString(36);
    const org = await OrganizationModel.create({
      name,
      slug: orgSlug,
      tier: SubscriptionTier.FREE,
      ownerId: req.userId,
    });

    await MembershipModel.create({
      organizationId: org._id,
      userId: req.userId,
      role: OrgRole.ORG_ADMIN,
    });

    res.status(201).json({ data: org });
  } catch (err) {
    next(err);
  }
});

// Add member (Admin only)
organizationRouter.post(
  '/:id/members',
  resolveTenant,
  requireOrgRole([OrgRole.ORG_ADMIN]),
  async (req: TenantRequest, res, next) => {
    try {
      const { targetUserId, role } = req.body;
      if (!targetUserId) {
        res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'targetUserId is required' } });
        return;
      }

      const assignedRole = Object.values(OrgRole).includes(role) ? role : OrgRole.VIEWER;
      const membership = await MembershipModel.findOneAndUpdate(
        { organizationId: req.params['id'], userId: targetUserId },
        { role: assignedRole },
        { upsert: true, new: true },
      );

      res.status(200).json({ data: membership });
    } catch (err) {
      next(err);
    }
  },
);
