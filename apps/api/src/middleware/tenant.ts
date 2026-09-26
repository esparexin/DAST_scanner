import type { Response, NextFunction } from 'express';
import { MembershipModel, OrganizationModel } from '@securityscan/database';
import { OrgRole } from '@securityscan/contracts';
import type { AuthRequest } from './auth.js';

export interface TenantRequest extends AuthRequest {
  organizationId?: string;
  orgRole?: OrgRole;
}

/**
 * Middleware that resolves tenant context (Organization) for authenticated requests.
 * Uses x-organization-id header, or defaults to the user's first available organization.
 */
export async function resolveTenant(
  req: TenantRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  if (!req.userId) {
    res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'User authentication required' } });
    return;
  }

  const requestedOrgId = req.headers['x-organization-id'] as string | undefined;

  try {
    let membership;
    if (requestedOrgId) {
      membership = await MembershipModel.findOne({
        organizationId: requestedOrgId,
        userId: req.userId,
      });
      if (!membership) {
        res.status(403).json({
          error: { code: 'FORBIDDEN', message: 'You are not a member of the requested organization' },
        });
        return;
      }
    } else {
      // Default to first membership
      membership = await MembershipModel.findOne({ userId: req.userId }).sort({ createdAt: 1 });
      if (!membership) {
        // Automatically create a default personal organization if none exists
        const defaultOrg = await OrganizationModel.create({
          name: 'Personal Workspace',
          slug: `personal-${req.userId.slice(-6)}-${Date.now().toString(36)}`,
          ownerId: req.userId,
        });
        membership = await MembershipModel.create({
          organizationId: defaultOrg._id,
          userId: req.userId,
          role: OrgRole.ORG_ADMIN,
        });
      }
    }

    req.organizationId = membership.organizationId.toString();
    req.orgRole = membership.role as OrgRole;
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
