export interface PortSwiggerTopic {
  topic: string;
  url: string;
  description: string;
  relatedCwe: string[];
}

export const PORTSWIGGER_REFERENCES: Record<string, PortSwiggerTopic> = {
  'sql-injection': {
    topic: 'SQL Injection',
    url: 'https://portswigger.net/web-security/sql-injection',
    description: 'Vulnerabilities allowing attackers to interfere with queries an application makes to its database.',
    relatedCwe: ['CWE-89'],
  },
  'cross-site-scripting': {
    topic: 'Cross-Site Scripting (XSS)',
    url: 'https://portswigger.net/web-security/cross-site-scripting',
    description: 'Vulnerabilities enabling attackers to inject client-side scripts into web pages viewed by other users.',
    relatedCwe: ['CWE-79'],
  },
  'csrf': {
    topic: 'Cross-Site Request Forgery (CSRF)',
    url: 'https://portswigger.net/web-security/csrf',
    description: 'Inducing users to perform unintended actions in a web application where they are currently authenticated.',
    relatedCwe: ['CWE-352'],
  },
  'ssrf': {
    topic: 'Server-Side Request Forgery (SSRF)',
    url: 'https://portswigger.net/web-security/ssrf',
    description: 'Coercing the server to make HTTP requests to an arbitrary domain of the attackers choosing.',
    relatedCwe: ['CWE-918'],
  },
  'path-traversal': {
    topic: 'File Path Traversal',
    url: 'https://portswigger.net/web-security/file-path-traversal',
    description: 'Allowing attackers to read arbitrary files on the server running an application.',
    relatedCwe: ['CWE-22'],
  },
  'access-control': {
    topic: 'Access Control Vulnerabilities & IDOR',
    url: 'https://portswigger.net/web-security/access-control',
    description: 'Failures in enforcing restrictions on who can execute actions or access resources.',
    relatedCwe: ['CWE-285', 'CWE-639'],
  },
  'cors': {
    topic: 'Cross-Origin Resource Sharing (CORS)',
    url: 'https://portswigger.net/web-security/cors',
    description: 'Configuration flaws allowing malicious websites to read sensitive data across origin boundaries.',
    relatedCwe: ['CWE-942'],
  },
  'clickjacking': {
    topic: 'Clickjacking',
    url: 'https://portswigger.net/web-security/clickjacking',
    description: 'Deceiving users into clicking hidden or transparent UI elements layered over an application.',
    relatedCwe: ['CWE-1021'],
  },
  'graphql': {
    topic: 'GraphQL API Vulnerabilities',
    url: 'https://portswigger.net/web-security/graphql',
    description: 'Insecure GraphQL implementations, unrestricted introspection, and query batching or depth abuse.',
    relatedCwe: ['CWE-200', 'CWE-400'],
  },
  'jwt': {
    topic: 'JWT Attacks',
    url: 'https://portswigger.net/web-security/jwt',
    description: 'Attacking JSON Web Token implementations via algorithm confusion, none-algorithm, and weak signing keys.',
    relatedCwe: ['CWE-287', 'CWE-345'],
  },
};
