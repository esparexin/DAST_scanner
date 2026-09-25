export interface WstgItem {
  id: string; // e.g. 'WSTG-INPV-05'
  category: string;
  name: string;
  description: string;
  cwes: string[];
}

export const WSTG_V42: Record<string, WstgItem> = {
  'WSTG-INFO-01': {
    id: 'WSTG-INFO-01',
    category: 'Information Gathering',
    name: 'Conduct Search Engine Discovery Reconnaissance',
    description: 'Test search engine discovery and reconnaissance for information leakage.',
    cwes: ['CWE-200'],
  },
  'WSTG-INFO-02': {
    id: 'WSTG-INFO-02',
    category: 'Information Gathering',
    name: 'Fingerprint Web Server',
    description: 'Determine the version and type of web server running to identify known weaknesses.',
    cwes: ['CWE-200'],
  },
  'WSTG-CONF-07': {
    id: 'WSTG-CONF-07',
    category: 'Configuration and Deployment Management',
    name: 'Test HTTP Strict Transport Security & Security Headers',
    description: 'Check for missing or misconfigured security headers including HSTS, X-Content-Type-Options, CSP, and CORS.',
    cwes: ['CWE-693', 'CWE-319', 'CWE-942', 'CWE-1021'],
  },
  'WSTG-ATHN-01': {
    id: 'WSTG-ATHN-01',
    category: 'Authentication Testing',
    name: 'Testing for Credentials Transported over an Encrypted Channel',
    description: 'Ensure credentials and sensitive tokens are transmitted only over encrypted channels.',
    cwes: ['CWE-319'],
  },
  'WSTG-ATHN-07': {
    id: 'WSTG-ATHN-07',
    category: 'Authentication Testing',
    name: 'Testing for Weak Password Policy & Rate Limiting',
    description: 'Verify login mechanisms enforce rate limiting and lockout protections against automated credential guessing.',
    cwes: ['CWE-307'],
  },
  'WSTG-SESS-02': {
    id: 'WSTG-SESS-02',
    category: 'Session Management Testing',
    name: 'Testing for Cookies Attributes',
    description: 'Verify cookies have Secure, HttpOnly, and appropriate SameSite flags configured.',
    cwes: ['CWE-614', 'CWE-1004', 'CWE-1275'],
  },
  'WSTG-SESS-05': {
    id: 'WSTG-SESS-05',
    category: 'Session Management Testing',
    name: 'Testing for Cross Site Request Forgery',
    description: 'Verify sensitive actions require unpredictable CSRF tokens or SameSite protections.',
    cwes: ['CWE-352'],
  },
  'WSTG-ATHZ-01': {
    id: 'WSTG-ATHZ-01',
    category: 'Authorization Testing',
    name: 'Testing Directory Traversal File Include',
    description: 'Test input parameters for path traversal patterns accessing local or remote filesystem resources.',
    cwes: ['CWE-22'],
  },
  'WSTG-ATHZ-02': {
    id: 'WSTG-ATHZ-02',
    category: 'Authorization Testing',
    name: 'Testing for Bypassing Authorization Schema',
    description: 'Test access to administrative or elevated functionality from unprivileged user accounts.',
    cwes: ['CWE-285'],
  },
  'WSTG-ATHZ-04': {
    id: 'WSTG-ATHZ-04',
    category: 'Authorization Testing',
    name: 'Testing for Insecure Direct Object References (IDOR/BOLA)',
    description: 'Verify authorization is enforced when client modifies object references (IDs, filenames, keys).',
    cwes: ['CWE-639'],
  },
  'WSTG-INPV-01': {
    id: 'WSTG-INPV-01',
    category: 'Input Validation Testing',
    name: 'Testing for Reflected Cross Site Scripting',
    description: 'Identify unvalidated and unescaped user input reflected in HTML or script contexts.',
    cwes: ['CWE-79'],
  },
  'WSTG-INPV-02': {
    id: 'WSTG-INPV-02',
    category: 'Input Validation Testing',
    name: 'Testing for Stored Cross Site Scripting',
    description: 'Identify stored input rendered in application views without context-appropriate encoding.',
    cwes: ['CWE-79'],
  },
  'WSTG-INPV-05': {
    id: 'WSTG-INPV-05',
    category: 'Input Validation Testing',
    name: 'Testing for SQL Injection',
    description: 'Identify user input concatenated into database query strings causing error or boolean differences.',
    cwes: ['CWE-89'],
  },
  'WSTG-INPV-19': {
    id: 'WSTG-INPV-19',
    category: 'Input Validation Testing',
    name: 'Testing for Server-Side Request Forgery',
    description: 'Identify parameters that induce the server to initiate arbitrary network requests.',
    cwes: ['CWE-918'],
  },
  'WSTG-APIT-01': {
    id: 'WSTG-APIT-01',
    category: 'API Testing',
    name: 'Testing GraphQL and REST API Implementations',
    description: 'Test API schema consistency, query complexity, introspection, and parameter handling.',
    cwes: ['CWE-20', 'CWE-400'],
  },
};
