export interface CweItem {
  id: string; // e.g. 'CWE-89'
  name: string;
  description: string;
  parentCwe?: string;
}

export const CWE_CATALOG: Record<string, CweItem> = {
  'CWE-20': {
    id: 'CWE-20',
    name: 'Improper Input Validation',
    description: 'The product receives input or data, but does not validate or incorrectly validates that the input has the properties that are required to process the data safely.',
  },
  'CWE-22': {
    id: 'CWE-22',
    name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
    description: 'The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.',
    parentCwe: 'CWE-20',
  },
  'CWE-79': {
    id: 'CWE-79',
    name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
    description: 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
    parentCwe: 'CWE-20',
  },
  'CWE-89': {
    id: 'CWE-89',
    name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
    description: 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.',
    parentCwe: 'CWE-20',
  },
  'CWE-200': {
    id: 'CWE-200',
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
    description: 'The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.',
  },
  'CWE-285': {
    id: 'CWE-285',
    name: 'Improper Authorization',
    description: 'The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.',
  },
  'CWE-287': {
    id: 'CWE-287',
    name: 'Improper Authentication',
    description: 'When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.',
  },
  'CWE-307': {
    id: 'CWE-307',
    name: 'Improper Restriction of Excessive Authentication Attempts',
    description: 'The software does not implement sufficient limits for authentication attempts, making it susceptible to brute-force attacks.',
  },
  'CWE-319': {
    id: 'CWE-319',
    name: 'Cleartext Transmission of Sensitive Information',
    description: 'The software transmits sensitive information in cleartext over a communication channel that can be sniffed by unauthorized actors.',
  },
  'CWE-352': {
    id: 'CWE-352',
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent HTTP request was intentionally provided by the user who submitted the request.',
  },
  'CWE-614': {
    id: 'CWE-614',
    name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    description: 'The software transmits a sensitive cookie over an HTTPS session without the Secure flag, making it vulnerable to transmission over unencrypted HTTP.',
  },
  'CWE-639': {
    id: 'CWE-639',
    name: 'Authorization Bypass Through User-Controlled Key (IDOR/BOLA)',
    description: 'The system authorization check for accessing an object uses client-provided data without verifying whether the user is authorized for that specific object.',
    parentCwe: 'CWE-285',
  },
  'CWE-693': {
    id: 'CWE-693',
    name: 'Protection Mechanism Failure',
    description: 'The product does not properly implement or enforce defensive protections such as security headers or content restrictions.',
  },
  'CWE-770': {
    id: 'CWE-770',
    name: 'Allocation of Resources Without Limits or Throttling',
    description: 'The software allocates resources without sufficient limits on quantity or frequency, leading to resource exhaustion.',
  },
  'CWE-918': {
    id: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, without sufficiently verifying that the destination is safe.',
  },
  'CWE-942': {
    id: 'CWE-942',
    name: 'Permissive Cross-origin Resource Sharing Policy',
    description: 'The software configures Cross-Origin Resource Sharing (CORS) in an overly permissive manner, allowing unauthorized domains to read sensitive response data.',
  },
  'CWE-1004': {
    id: 'CWE-1004',
    name: 'Sensitive Cookie Without HttpOnly Flag',
    description: 'The software sets a sensitive cookie without the HttpOnly attribute, allowing client-side scripts to access it.',
  },
  'CWE-1021': {
    id: 'CWE-1021',
    name: 'Improper Restriction of Rendered UI Layers or Frames',
    description: 'The web application does not restrict framing via X-Frame-Options or CSP frame-ancestors, enabling clickjacking attacks.',
  },
  'CWE-1275': {
    id: 'CWE-1275',
    name: 'Sensitive Cookie with Improper SameSite Attribute',
    description: 'The software sets a cookie without a proper SameSite attribute (Lax or Strict), increasing risk of CSRF attacks.',
  },
};
