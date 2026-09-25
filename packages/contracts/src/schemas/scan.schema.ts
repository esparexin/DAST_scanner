import { z } from 'zod';
import { ScanProfile } from '../enums.js';

export const CreateScanSchema = z.object({
  projectId: z.string().min(1),
  targetId: z.string().min(1),
  profile: z.nativeEnum(ScanProfile).optional().default(ScanProfile.WEB_STANDARD),
  dryRun: z.boolean().optional().default(false),
  authProfileIds: z.array(z.string()).optional().default([]),
  enabledCategories: z.array(z.string()).optional(),
  excludedChecks: z.array(z.string()).optional().default([]),
});

export type CreateScanInput = z.infer<typeof CreateScanSchema>;
