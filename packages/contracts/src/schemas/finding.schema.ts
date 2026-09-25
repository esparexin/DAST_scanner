import { z } from 'zod';
import { Severity, Confidence, FindingStatus, DetectionCategory } from '../enums.js';

export const UpdateFindingStatusSchema = z.object({
  status: z.nativeEnum(FindingStatus),
  reason: z.string().max(2000).optional(),
});

export const FindingFilterSchema = z.object({
  scanId: z.string().optional(),
  projectId: z.string().optional(),
  targetId: z.string().optional(),
  severity: z.nativeEnum(Severity).optional(),
  confidence: z.nativeEnum(Confidence).optional(),
  status: z.nativeEnum(FindingStatus).optional(),
  category: z.nativeEnum(DetectionCategory).optional(),
  ruleId: z.string().optional(),
  page: z.number().int().min(1).optional().default(1),
  limit: z.number().int().min(1).max(100).optional().default(20),
});

export type UpdateFindingStatusInput = z.infer<typeof UpdateFindingStatusSchema>;
export type FindingFilterInput = z.infer<typeof FindingFilterSchema>;
