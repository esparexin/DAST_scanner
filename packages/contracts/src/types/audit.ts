import type { AuditAction } from '../enums.js';

export interface IAuditLog {
  id: string;
  action: AuditAction;
  actorId: string;
  actorEmail?: string;
  resourceType: string;
  resourceId: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  timestamp: Date;
}
