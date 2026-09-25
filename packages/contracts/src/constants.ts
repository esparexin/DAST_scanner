// Default safety limits
export const DEFAULT_MAX_REQUESTS_PER_SECOND = 10;
export const DEFAULT_MAX_CONCURRENCY = 5;
export const DEFAULT_MAX_REQUESTS = 10_000;
export const DEFAULT_MAX_CRAWL_DEPTH = 5;
export const DEFAULT_MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10 MB
export const DEFAULT_MAX_SCAN_DURATION = 3600; // 1 hour
export const DEFAULT_TIMEOUT_PER_REQUEST = 30; // 30 seconds

// Maximum safety limits (cannot be exceeded)
export const MAX_REQUESTS_PER_SECOND_LIMIT = 100;
export const MAX_CONCURRENCY_LIMIT = 20;
export const MAX_REQUESTS_LIMIT = 100_000;
export const MAX_CRAWL_DEPTH_LIMIT = 20;
export const MAX_RESPONSE_SIZE_LIMIT = 50 * 1024 * 1024; // 50 MB
export const MAX_SCAN_DURATION_LIMIT = 86_400; // 24 hours
export const MAX_TIMEOUT_PER_REQUEST_LIMIT = 120; // 120 seconds
export const MAX_REDIRECT_CHAIN = 10;

// Private IP ranges (blocked by default for SSRF protection)
export const PRIVATE_IP_RANGES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '0.0.0.0/8',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
] as const;

// User agent
export const DEFAULT_USER_AGENT = 'SecurityScan/0.1.0 (Authorized Security Testing)';

// Redaction patterns
export const SENSITIVE_HEADER_PATTERNS = [
  /^authorization$/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /^x-api-key$/i,
  /^x-auth-token$/i,
  /^proxy-authorization$/i,
] as const;

export const SENSITIVE_BODY_PATTERNS = [
  /password/i,
  /passwd/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /access[_-]?key/i,
  /private[_-]?key/i,
  /client[_-]?secret/i,
] as const;
