/**
 * Centralised API environment configuration.
 *
 * All environment variables are read and validated here at startup.
 * This is the SSOT for all env-based config values in apps/api.
 * Import from this module — do NOT call process.env directly in routes or middleware.
 */

const isTestEnv = process.env['NODE_ENV'] === 'test';

function requireEnv(key: string, fallback?: string): string {
  const value = process.env[key];
  if (value) return value;
  if (fallback !== undefined) {
    if (!isTestEnv && key === 'JWT_SECRET' && fallback === 'change-me-in-production') {
      throw new Error(
        `[config] JWT_SECRET environment variable is not set. ` +
          `Set a cryptographically random secret before starting the API server.`,
      );
    }
    return fallback;
  }
  throw new Error(`[config] Required environment variable '${key}' is not set.`);
}

/**
 * JWT authentication configuration.
 * JWT_SECRET must be set in non-test environments.
 */
export const JWT_SECRET = requireEnv('JWT_SECRET', 'change-me-in-production');

/**
 * JWT expiry duration string accepted by jsonwebtoken (e.g. '24h', '7d', '60s').
 * Defaults to '24h' if not set.
 */
export const JWT_EXPIRES_IN = requireEnv('JWT_EXPIRES_IN', '24h');

/**
 * HTTP server port.
 */
export const PORT = parseInt(process.env['PORT'] ?? '3001', 10);

/**
 * Node environment.
 */
export const NODE_ENV = process.env['NODE_ENV'] ?? 'development';
