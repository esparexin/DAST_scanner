import { z } from 'zod';
import { AuthType, AuthProfileRole } from '../enums.js';

export const AuthConfigurationSchema = z.object({
  cookies: z.record(z.string()).optional(),
  token: z.string().optional(),
  apiKeyHeader: z.string().optional(),
  apiKeyValue: z.string().optional(),
  oauthTokenUrl: z.string().url().optional(),
  oauthClientId: z.string().optional(),
  oauthClientSecret: z.string().optional(),
  oauthScope: z.string().optional(),
  oauthGrantType: z.string().optional(),
  customHeaders: z.record(z.string()).optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  loginUrl: z.string().url().optional(),
  loginMethod: z.string().optional(),
  loginBody: z.string().optional(),
});

export const CreateAuthProfileSchema = z.object({
  projectId: z.string().min(1),
  name: z.string().min(1).max(200).trim(),
  role: z.nativeEnum(AuthProfileRole).optional().default(AuthProfileRole.USER),
  type: z.nativeEnum(AuthType),
  configuration: AuthConfigurationSchema,
});

export type CreateAuthProfileInput = z.infer<typeof CreateAuthProfileSchema>;
