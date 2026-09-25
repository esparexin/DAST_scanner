import { z } from 'zod';
import { ReportFormat } from '../enums.js';

export const GenerateReportSchema = z.object({
  scanId: z.string().min(1),
  format: z.nativeEnum(ReportFormat).optional().default(ReportFormat.JSON),
  title: z.string().min(1).max(500).trim().optional(),
});

export type GenerateReportInput = z.infer<typeof GenerateReportSchema>;
