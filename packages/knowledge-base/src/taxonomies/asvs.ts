export interface AsvsItem {
  id: string;
  chapter: string;
  level: 1 | 2 | 3;
  requirement: string;
}

export const ASVS_V403: Record<string, AsvsItem> = {
  'V2.1.1': {
    id: 'V2.1.1',
    chapter: 'V2 Authentication',
    level: 1,
    requirement: 'Verify that user set passwords are at least 12 characters in length (or 8 with additional controls).',
  },
  'V2.2.1': {
    id: 'V2.2.1',
    chapter: 'V2 Authentication',
    level: 1,
    requirement: 'Verify that anti-automation controls are effective at mitigating credential stuffing and brute-force.',
  },
  'V3.4.1': {
    id: 'V3.4.1',
    chapter: 'V3 Session Management',
    level: 1,
    requirement: 'Verify that cookie-based session tokens have the Secure attribute set.',
  },
  'V3.4.2': {
    id: 'V3.4.2',
    chapter: 'V3 Session Management',
    level: 1,
    requirement: 'Verify that cookie-based session tokens have the HttpOnly attribute set.',
  },
  'V3.4.3': {
    id: 'V3.4.3',
    chapter: 'V3 Session Management',
    level: 1,
    requirement: 'Verify that cookie-based session tokens use the SameSite attribute to mitigate CSRF attacks.',
  },
  'V4.1.1': {
    id: 'V4.1.1',
    chapter: 'V4 Access Control',
    level: 1,
    requirement: 'Verify that the application enforces access control rules on a trusted server-side system.',
  },
  'V4.1.2': {
    id: 'V4.1.2',
    chapter: 'V4 Access Control',
    level: 1,
    requirement: 'Verify that all user and data attributes are validated to ensure the user has permission to access the target object (IDOR/BOLA).',
  },
  'V4.1.3': {
    id: 'V4.1.3',
    chapter: 'V4 Access Control',
    level: 1,
    requirement: 'Verify that the principle of least privilege exists, granting users access only to required functions.',
  },
  'V5.3.1': {
    id: 'V5.3.1',
    chapter: 'V5 Validation and Sanitization',
    level: 1,
    requirement: 'Verify that output encoding is relevant for the interpreter and context required (XSS prevention).',
  },
  'V5.3.4': {
    id: 'V5.3.4',
    chapter: 'V5 Validation and Sanitization',
    level: 1,
    requirement: 'Verify that parameterized queries or ORMs are used to prevent SQL and other database injections.',
  },
  'V12.3.1': {
    id: 'V12.3.1',
    chapter: 'V12 File and Resources',
    level: 1,
    requirement: 'Verify that user-supplied path components are rejected or sanitized to prevent path traversal.',
  },
  'V12.6.1': {
    id: 'V12.6.1',
    chapter: 'V12 File and Resources',
    level: 1,
    requirement: 'Verify that the web server only accesses authorized remote resources, validating URL schemes and destinations (SSRF).',
  },
  'V13.1.4': {
    id: 'V13.1.4',
    chapter: 'V13 API and Web Service',
    level: 1,
    requirement: 'Verify that GraphQL schemas enforce query depth limits and query cost analysis to prevent DoS.',
  },
  'V14.4.1': {
    id: 'V14.4.1',
    chapter: 'V14 Configuration',
    level: 1,
    requirement: 'Verify that every HTTP response contains a Content-Security-Policy (CSP) header.',
  },
  'V14.4.2': {
    id: 'V14.4.2',
    chapter: 'V14 Configuration',
    level: 1,
    requirement: 'Verify that all responses include X-Content-Type-Options: nosniff.',
  },
  'V14.4.3': {
    id: 'V14.4.3',
    chapter: 'V14 Configuration',
    level: 1,
    requirement: 'Verify that HTTP Strict Transport Security (HSTS) is enabled with appropriate max-age.',
  },
  'V14.4.6': {
    id: 'V14.4.6',
    chapter: 'V14 Configuration',
    level: 1,
    requirement: 'Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header is not set to wildcard (*) for authenticated resources.',
  },
};
