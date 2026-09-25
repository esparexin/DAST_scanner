import { z } from 'zod';
import { TargetEnvironment, AuthorizationState } from '../enums.js';
import { ScopeSchema } from './scope.schema.js';

export const CreateTargetSchema = z.object({
  projectId: z.string().min(1),
  name: z.string().min(1).max(200).trim(),
  baseUrl: z.string().url('Must be a valid URL'),
  environment: z
    .nativeEnum(TargetEnvironment)
    .optional()
    .default(TargetEnvironment.TESTING),
  scope: ScopeSchema,
});

export const UpdateTargetSchema = z.object({
  name: z.string().min(1).max(200).trim().optional(),
  baseUrl: z.string().url('Must be a valid URL').optional(),
  environment: z.nativeEnum(TargetEnvironment).optional(),
  authorization: z.nativeEnum(AuthorizationState).optional(),
  scope: ScopeSchema.partial().optional(),
});

export type CreateTargetInput = z.infer<typeof CreateTargetSchema>;
export type UpdateTargetInput = z.infer<typeof UpdateTargetSchema>;
