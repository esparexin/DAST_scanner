import type { AuthType, AuthProfileRole } from '../enums.js';

export interface IAuthProfile {
  id: string;
  projectId: string;
  name: string;
  role: AuthProfileRole;
  type: AuthType;
  /** Configuration is stored encrypted at rest. Never returned to frontend. */
  configuration: IAuthConfiguration;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface IAuthConfiguration {
  // Cookie/Session
  cookies?: Record<string, string>;

  // Bearer/JWT
  token?: string;

  // API Key
  apiKeyHeader?: string;
  apiKeyValue?: string;

  // OAuth 2.0
  oauthTokenUrl?: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthScope?: string;
  oauthGrantType?: string;

  // Custom Headers
  customHeaders?: Record<string, string>;

  // Username/Password (for session-based login)
  username?: string;
  password?: string;
  loginUrl?: string;
  loginMethod?: string;
  loginBody?: string;
}

export interface ICreateAuthProfile {
  projectId: string;
  name: string;
  role?: AuthProfileRole;
  type: AuthType;
  configuration: IAuthConfiguration;
}

/** API response shape - credentials are always redacted */
export interface IAuthProfileResponse {
  id: string;
  projectId: string;
  name: string;
  role: AuthProfileRole;
  type: AuthType;
  isActive: boolean;
  hasCredentials: boolean;
  createdAt: Date;
  updatedAt: Date;
}
