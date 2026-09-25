export interface CweItem {
  id: string;
  name: string;
  description: string;
}

export const CWE_CATALOG: Record<string, CweItem> = {
  'CWE-22': {
    id: 'CWE-22',
    name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
    description: 'The software uses external input to construct a pathname intended to identify a file or directory located underneath a restricted parent directory.',
  },
  'CWE-79': {
    id: 'CWE-79',
    name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
    description: 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page.',
  },
  'CWE-89': {
    id: 'CWE-89',
    name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
    description: 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component.',
  },
  'CWE-200': {
    id: 'CWE-200',
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
    description: 'The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.',
  },
  'CWE-285': {
    id: 'CWE-285',
    name: 'Improper Authorization',
    description: 'The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource.',
  },
  'CWE-287': {
    id: 'CWE-287',
    name: 'Improper Authentication',
    description: 'When an actor claims to have a given identity, the software does not prove or improperly proves that the claim is correct.',
  },
  'CWE-307': {
    id: 'CWE-307',
    name: 'Improper Restriction of Excessive Authentication Attempts',
    description: 'The software does not properly restrict the number of consecutive authentication attempts by an actor.',
  },
  'CWE-319': {
    id: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Information',
    description: 'The software transmits sensitive data over an unencrypted communication channel.',
  },
  'CWE-352': {
    id: 'CWE-352',
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user.',
  },
  'CWE-614': {
    id: 'CWE-614',
    name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    description: 'The software transmits a sensitive cookie over an SSL/TLS connection without the Secure attribute.',
  },
  'CWE-639': {
    id: 'CWE-639',
    name: 'Authorization Bypass Through User-Controlled Key (IDOR/BOLA)',
    description: 'The system user-controlled key to select a record or resource without verifying the user has authorization for that record.',
  },
  'CWE-693': {
    id: 'CWE-693',
    name: 'Protection Mechanism Failure',
    description: 'The product does not properly enforce protection mechanisms such as security headers or content boundaries.',
  },
  'CWE-918': {
    id: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'The web server receives a URL from an upstream component and retrieves the contents without adequate validation.',
  },
  'CWE-942': {
    id: 'CWE-942',
    name: 'Permissive Cross-Domain Policy with Untrusted Domains (CORS)',
    description: 'The application uses overly permissive CORS policies allowing untrusted domains access to restricted responses.',
  },
  'CWE-1004': {
    id: 'CWE-1004',
    name: 'Sensitive Cookie Without HttpOnly Flag',
    description: 'The software creates a cookie without the HttpOnly flag, allowing client-side scripts to read the cookie contents.',
  },
  'CWE-1021': {
    id: 'CWE-1021',
    name: 'Improper Restriction of Rendered UI Layers or Frames (Clickjacking)',
    description: 'The web application does not restrict rendering within frames or iframes, enabling clickjacking attacks.',
  },
  'CWE-1275': {
    id: 'CWE-1275',
    name: 'Sensitive Cookie with Improper SameSite Attribute',
    description: 'The software sets a sensitive cookie without the SameSite attribute set to Strict or Lax.',
  },
};
