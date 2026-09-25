export interface OwaspTop10Item {
  id: string;
  year: 2021;
  code: string;
  name: string;
  description: string;
  cweSample: string[];
}

export const OWASP_TOP_10_2021: Record<string, OwaspTop10Item> = {
  'A01:2021': {
    id: 'A01:2021',
    year: 2021,
    code: 'A01',
    name: 'Broken Access Control',
    description: 'Failures in enforcing access controls where users can act outside their intended permissions.',
    cweSample: ['CWE-22', 'CWE-285', 'CWE-639', 'CWE-862'],
  },
  'A02:2021': {
    id: 'A02:2021',
    year: 2021,
    code: 'A02',
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography (or lack thereof), often leading to exposure of sensitive data.',
    cweSample: ['CWE-259', 'CWE-319', 'CWE-327', 'CWE-331'],
  },
  'A03:2021': {
    id: 'A03:2021',
    year: 2021,
    code: 'A03',
    name: 'Injection',
    description: 'Vulnerabilities where hostile data sent to an interpreter leads to unauthorized commands or access.',
    cweSample: ['CWE-79', 'CWE-89', 'CWE-77', 'CWE-94'],
  },
  'A04:2021': {
    id: 'A04:2021',
    year: 2021,
    code: 'A04',
    name: 'Insecure Design',
    description: 'Risks related to design and architectural flaws, requiring threat modeling and secure design patterns.',
    cweSample: ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522'],
  },
  'A05:2021': {
    id: 'A05:2021',
    year: 2021,
    code: 'A05',
    name: 'Security Misconfiguration',
    description: 'Missing appropriate security hardening, improperly configured permissions, or verbose errors.',
    cweSample: ['CWE-16', 'CWE-200', 'CWE-693', 'CWE-942', 'CWE-1004'],
  },
  'A06:2021': {
    id: 'A06:2021',
    year: 2021,
    code: 'A06',
    name: 'Vulnerable and Outdated Components',
    description: 'Using unsupported, outdated, or vulnerable third-party components and libraries.',
    cweSample: ['CWE-1104'],
  },
  'A07:2021': {
    id: 'A07:2021',
    year: 2021,
    code: 'A07',
    name: 'Identification and Authentication Failures',
    description: 'Weaknesses in confirmation of the users identity, authentication, or session management.',
    cweSample: ['CWE-287', 'CWE-384', 'CWE-613'],
  },
  'A08:2021': {
    id: 'A08:2021',
    year: 2021,
    code: 'A08',
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure that does not protect against integrity violations (untrusted plugins, desync).',
    cweSample: ['CWE-502', 'CWE-829'],
  },
  'A09:2021': {
    id: 'A09:2021',
    year: 2021,
    code: 'A09',
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging, monitoring, and alerting enabling undetected breaches.',
    cweSample: ['CWE-778', 'CWE-117'],
  },
  'A10:2021': {
    id: 'A10:2021',
    year: 2021,
    code: 'A10',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Flaws occurring when a web application fetches a remote resource without validating the user-supplied URL.',
    cweSample: ['CWE-918'],
  },
};
