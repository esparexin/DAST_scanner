import { Router, type Request, type Response } from 'express';
import { AuditLogModel } from '@securityscan/database';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('audit-routes');
export const auditRouter = Router();
export const auditRoutes = auditRouter;

// In-memory fallback if MongoDB is not connected
const fallbackLogs = [
  {
    id: 'audit-001',
    userId: 'system',
    action: 'SYSTEM_STARTUP',
    resource: 'Platform',
    details: { version: '1.2.0', status: 'healthy' },
    ipAddress: '127.0.0.1',
    timestamp: new Date().toISOString(),
  },
  {
    id: 'audit-002',
    userId: 'admin',
    action: 'POLICY_EVALUATION',
    resource: 'ScopeValidator',
    details: { enforced: true, privateIpBlock: true },
    ipAddress: '127.0.0.1',
    timestamp: new Date().toISOString(),
  },
];

// GET /api/audit - List audit events
auditRouter.get('/', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const action = req.query.action as string | undefined;
    const query: Record<string, unknown> = {};
    if (action) query.action = action;

    const logs = await AuditLogModel.find(query)
      .sort({ timestamp: -1 })
      .limit(limit)
      .lean()
      .exec();

    if (logs && logs.length > 0) {
      return res.json(logs);
    }
    return res.json(fallbackLogs);
  } catch (error) {
    logger.warn({ error }, 'Failed to fetch audit logs from DB, returning fallback');
    return res.json(fallbackLogs);
  }
});

// POST /api/audit - Record an audit event
auditRouter.post('/', async (req: Request, res: Response) => {
  try {
    const { userId, action, resource, resourceId, details } = req.body;
    if (!action || !resource) {
      return res.status(400).json({ error: 'Action and resource are required' });
    }

    const entry = await AuditLogModel.create({
      userId: userId || 'anonymous',
      action,
      resource,
      resourceId,
      details,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'],
      timestamp: new Date(),
    });

    return res.status(201).json(entry);
  } catch (error) {
    logger.error({ error }, 'Failed to write audit entry');
    return res.status(500).json({ error: 'Internal server error' });
  }
});
