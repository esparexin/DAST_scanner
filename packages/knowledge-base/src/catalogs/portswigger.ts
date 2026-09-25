export interface PortSwiggerTopic {
  id: string;
  name: string;
  url: string;
  relatedCwes: string[];
}

export const PORTSWIGGER_TOPICS: Record<string, PortSwiggerTopic> = {
  'sql-injection': {
    id: 'sql-injection',
    name: 'SQL Injection',
    url: 'https://portswigger.net/web-security/sql-injection',
    relatedCwes: ['CWE-89'],
  },
  'cross-site-scripting': {
    id: 'cross-site-scripting',
    name: 'Cross-site Scripting (XSS)',
    url: 'https://portswigger.net/web-security/cross-site-scripting',
    relatedCwes: ['CWE-79'],
  },
  'cross-site-request-forgery': {
    id: 'cross-site-request-forgery',
    name: 'Cross-site Request Forgery (CSRF)',
    url: 'https://portswigger.net/web-security/csrf',
    relatedCwes: ['CWE-352'],
  },
  'cors': {
    id: 'cors',
    name: 'Cross-Origin Resource Sharing (CORS)',
    url: 'https://portswigger.net/web-security/cors',
    relatedCwes: ['CWE-942'],
  },
  'clickjacking': {
    id: 'clickjacking',
    name: 'Clickjacking',
    url: 'https://portswigger.net/web-security/clickjacking',
    relatedCwes: ['CWE-1021'],
  },
  'ssrf': {
    id: 'ssrf',
    name: 'Server-Side Request Forgery (SSRF)',
    url: 'https://portswigger.net/web-security/ssrf',
    relatedCwes: ['CWE-918'],
  },
  'file-path-traversal': {
    id: 'file-path-traversal',
    name: 'File Path Traversal',
    url: 'https://portswigger.net/web-security/file-path-traversal',
    relatedCwes: ['CWE-22'],
  },
  'access-control': {
    id: 'access-control',
    name: 'Access Control Vulnerabilities & IDOR',
    url: 'https://portswigger.net/web-security/access-control',
    relatedCwes: ['CWE-639', 'CWE-285'],
  },
  'graphql': {
    id: 'graphql',
    name: 'GraphQL API Vulnerabilities',
    url: 'https://portswigger.net/web-security/graphql',
    relatedCwes: ['CWE-200', 'CWE-400'],
  },
  'jwt': {
    id: 'jwt',
    name: 'JSON Web Token (JWT) Attacks',
    url: 'https://portswigger.net/web-security/jwt',
    relatedCwes: ['CWE-287', 'CWE-345'],
  },
  'oauth': {
    id: 'oauth',
    name: 'OAuth 2.0 Authentication Vulnerabilities',
    url: 'https://portswigger.net/web-security/oauth',
    relatedCwes: ['CWE-287', 'CWE-352'],
  },
};
