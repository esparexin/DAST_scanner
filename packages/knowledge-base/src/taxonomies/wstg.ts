export interface WstgItem {
  id: string;
  category: string;
  name: string;
  description: string;
}

export const WSTG_V42: Record<string, WstgItem> = {
  'WSTG-INFO-01': {
    id: 'WSTG-INFO-01',
    category: 'Information Gathering',
    name: 'Conduct Search Engine Discovery and Reconnaissance',
    description: 'Discovering publicly available application resources and sensitive info via search engines.',
  },
  'WSTG-INFO-02': {
    id: 'WSTG-INFO-02',
    category: 'Information Gathering',
    name: 'Fingerprint Web Server',
    description: 'Identifying the web server, versions, and active modules through response headers and banners.',
  },
  'WSTG-CONF-07': {
    id: 'WSTG-CONF-07',
    category: 'Configuration and Deployment Management',
    name: 'Test HTTP Strict Transport Security & Security Headers',
    description: 'Verifying proper enforcement of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and CORS.',
  },
  'WSTG-ATHN-01': {
    id: 'WSTG-ATHN-01',
    category: 'Authentication Testing',
    name: 'Testing for Credentials Transported over an Encrypted Channel',
    description: 'Confirming authentication credentials are never sent via cleartext HTTP.',
  },
  'WSTG-ATHN-07': {
    id: 'WSTG-ATHN-07',
    category: 'Authentication Testing',
    name: 'Testing for Weak Password Policy & Rate Limiting',
    description: 'Testing login endpoint resistance to automated credential brute-forcing and rate limits.',
  },
  'WSTG-SESS-02': {
    id: 'WSTG-SESS-02',
    category: 'Session Management Testing',
    name: 'Testing for Cookies Attributes',
    description: 'Verifying Set-Cookie flags: Secure, HttpOnly, SameSite (Strict/Lax), Domain, and Path.',
  },
  'WSTG-SESS-05': {
    id: 'WSTG-SESS-05',
    category: 'Session Management Testing',
    name: 'Testing for Cross Site Request Forgery (CSRF)',
    description: 'Validating Anti-CSRF tokens, SameSite policies, and state-changing request protections.',
  },
  'WSTG-ATHZ-01': {
    id: 'WSTG-ATHZ-01',
    category: 'Authorization Testing',
    name: 'Testing Directory Traversal and File Include',
    description: 'Testing access to arbitrary files and directories outside web document root.',
  },
  'WSTG-ATHZ-02': {
    id: 'WSTG-ATHZ-02',
    category: 'Authorization Testing',
    name: 'Testing for Bypassing Authorization Schema',
    description: 'Validating vertical access control restrictions between user and administrator roles.',
  },
  'WSTG-ATHZ-04': {
    id: 'WSTG-ATHZ-04',
    category: 'Authorization Testing',
    name: 'Testing for Insecure Direct Object References (IDOR/BOLA)',
    description: 'Validating horizontal access control restrictions between distinct tenant/user identities.',
  },
  'WSTG-INPV-01': {
    id: 'WSTG-INPV-01',
    category: 'Input Validation Testing',
    name: 'Testing for Reflected Cross Site Scripting',
    description: 'Verifying if user-supplied input is reflected in HTML output without context-aware sanitization.',
  },
  'WSTG-INPV-05': {
    id: 'WSTG-INPV-05',
    category: 'Input Validation Testing',
    name: 'Testing for SQL Injection',
    description: 'Verifying application inputs for SQL interpreter exploitation (error, boolean, time-based).',
  },
  'WSTG-INPV-19': {
    id: 'WSTG-INPV-19',
    category: 'Input Validation Testing',
    name: 'Testing for Server-Side Request Forgery',
    description: 'Testing if backend server can be compelled to request internal or forbidden external endpoints.',
  },
  'WSTG-APIT-01': {
    id: 'WSTG-APIT-01',
    category: 'API Testing',
    name: 'Testing GraphQL and REST APIs',
    description: 'Testing API endpoints for introspection, batching abuse, and excessive data exposure.',
  },
};
