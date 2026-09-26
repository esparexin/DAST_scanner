import type { Request, Response, NextFunction } from 'express';
import { MembershipModel, OrganizationModel } from '@securityscan/database';
import { OrgRole, SubscriptionTier } from '@securityscan/contracts';
import type { AuthRequest } from './auth.js';

export interface TenantRequest extends AuthRequest {
  organizationId?: string;
  orgRole?: OrgRole;
  orgTier?: SubscriptionTier;
}

/**
 * Middleware that resolves tenant context (Organization) for authenticated requests.
 * Uses x-organization-id header, or defaults to the user's first available organization.
 *
 * Typed as (req: Request) so Express's router.use() accepts it without casting.
 * The function mutates req to add TenantRequest fields — this is safe because
 * authenticate() always runs first and populates the AuthRequest fields.
 */
export async function resolveTenant(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  // Cast to TenantRequest internally — safe because authenticate() runs first
  const tenantReq = req as TenantRequest;
  if (!tenantReq.userId) {
    res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'User authentication required' } });
    return;
  }

  const requestedOrgId = req.headers['x-organization-id'] as string | undefined;

  try {
    let membership;
    if (requestedOrgId) {
      membership = await MembershipModel.findOne({
        organizationId: requestedOrgId,
        userId: tenantReq.userId,
      });
      if (!membership) {
        res.status(403).json({
          error: { code: 'FORBIDDEN', message: 'You are not a member of the requested organization' },
        });
        return;
      }
    } else {
      // Default to first membership
      membership = await MembershipModel.findOne({ userId: tenantReq.userId }).sort({ createdAt: 1 });
      if (!membership) {
        // Automatically create a default personal organization if none exists
        const defaultOrg = await OrganizationModel.create({
          name: 'Personal Workspace',
          slug: `personal-${tenantReq.userId!.slice(-6)}-${Date.now().toString(36)}`,
          ownerId: tenantReq.userId,
        });
        membership = await MembershipModel.create({
          organizationId: defaultOrg._id,
          userId: tenantReq.userId,
          role: OrgRole.ORG_ADMIN,
        });
      }
    }

    const org = await OrganizationModel.findById(membership.organizationId);
    tenantReq.organizationId = membership.organizationId.toString();
    tenantReq.orgRole = membership.role as OrgRole;
    tenantReq.orgTier = (org?.tier as SubscriptionTier) ?? SubscriptionTier.FREE;
    next();
  } catch (error) {
    next(error);
  }
}

/**
 * Role-Based Access Control (RBAC) gatekeeper for organization roles
 */
export function requireOrgRole(allowedRoles: OrgRole[]) {
  return (req: TenantRequest, res: Response, next: NextFunction): void => {
    if (!req.orgRole || !allowedRoles.includes(req.orgRole)) {
      res.status(403).json({
        error: {
          code: 'FORBIDDEN',
          message: `Insufficient organization permissions. Required one of: ${allowedRoles.join(', ')}`,
        },
      });
      return;
    }
    next();
  };
}
