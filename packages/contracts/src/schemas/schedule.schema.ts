import { z } from 'zod';
import { ScheduleFrequency, ScanProfile } from '../enums.js';

export const CreateScheduleSchema = z.object({
  name: z.string().min(1).max(200).trim(),
  projectId: z.string().min(1),
  targetId: z.string().min(1),
  profile: z.nativeEnum(ScanProfile).optional().default(ScanProfile.WEB_STANDARD),
  frequency: z.nativeEnum(ScheduleFrequency).optional(),
  /** Custom 5-field cron expression — required when frequency is CUSTOM */
  cron: z.string().optional(),
  enabled: z.boolean().optional().default(true),
});

export type CreateScheduleInput = z.infer<typeof CreateScheduleSchema>;

export const UpdateScheduleSchema = z.object({
  name: z.string().min(1).max(200).trim().optional(),
  profile: z.nativeEnum(ScanProfile).optional(),
  frequency: z.nativeEnum(ScheduleFrequency).optional(),
  cron: z.string().optional(),
  enabled: z.boolean().optional(),
});

export type UpdateScheduleInput = z.infer<typeof UpdateScheduleSchema>;
