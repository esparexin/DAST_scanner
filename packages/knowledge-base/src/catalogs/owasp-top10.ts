export interface OwaspTop10Item {
  id: string; // e.g. 'A01:2021'
  title: string;
  name: string;
  description: string;
  cwes: string[];
  remediationOverview: string;
}

export const OWASP_TOP_10_2021: Record<string, OwaspTop10Item> = {
  'A01:2021': {
    id: 'A01:2021',
    title: 'A01:2021 - Broken Access Control',
    name: 'Broken Access Control',
    description:
      'Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user limits.',
    cwes: ['CWE-22', 'CWE-285', 'CWE-639', 'CWE-862', 'CWE-863', 'CWE-352'],
    remediationOverview:
      'Except for public resources, deny access by default. Implement access control mechanisms once and re-use them throughout the application. Enforce record ownership and domain model authorization.',
  },
  'A02:2021': {
    id: 'A02:2021',
    title: 'A02:2021 - Cryptographic Failures',
    name: 'Cryptographic Failures',
    description:
      'Failures related to cryptography (previously known as Sensitive Data Exposure), which often leads to sensitive data exposure or system compromise. Common flaws include transmitting sensitive data in clear text, using weak or outdated cryptographic algorithms, and weak key management.',
    cwes: ['CWE-319', 'CWE-326', 'CWE-327', 'CWE-330'],
    remediationOverview:
      'Classify data processed, stored, or transmitted by an application. Apply controls per classification: encrypt data at rest using standard strong encryption, enforce TLS with modern ciphers and HSTS.',
  },
  'A03:2021': {
    id: 'A03:2021',
    title: 'A03:2021 - Injection',
    name: 'Injection',
    description:
      'Injection flaws, such as SQL, NoSQL, OS command, Object Relational Mapping (ORM), LDAP, and Expression Language (EL) or XML injection occur when untrusted data is sent to an interpreter as part of a command or query.',
    cwes: ['CWE-89', 'CWE-79', 'CWE-77', 'CWE-78', 'CWE-94'],
    remediationOverview:
      'Use a safe API which avoids interpreter invocation, use parameterized interfaces, or migrate to ORMs. Use positive or whitelist input validation and context-aware output encoding.',
  },
  'A04:2021': {
    id: 'A04:2021',
    title: 'A04:2021 - Insecure Design',
    name: 'Insecure Design',
    description:
      'Insecure design represents vulnerabilities related to design and architectural flaws. It calls for more use of threat modeling, secure design patterns, and reference architectures.',
    cwes: ['CWE-209', 'CWE-256', 'CWE-307', 'CWE-770'],
    remediationOverview:
      'Establish and use a secure development lifecycle with AppSec professionals. Use threat modeling for critical authentication, access control, and business workflows. Implement rate limiting and resource limits.',
  },
  'A05:2021': {
    id: 'A05:2021',
    title: 'A05:2021 - Security Misconfiguration',
    name: 'Security Misconfiguration',
    description:
      'Security misconfiguration is commonly seen as missing appropriate security hardening across the application stack, improper permissions on cloud services, unnecessary features enabled, default accounts/passwords, and verbose error messages.',
    cwes: ['CWE-16', 'CWE-693', 'CWE-1004', 'CWE-614', 'CWE-1275', 'CWE-942', 'CWE-200', 'CWE-1021'],
    remediationOverview:
      'A repeatable hardening process makes it fast and easy to deploy another environment that is properly locked down. Remove or do not install unused features and frameworks. Send security headers and enforce restrictive CORS.',
  },
  'A06:2021': {
    id: 'A06:2021',
    title: 'A06:2021 - Vulnerable and Outdated Components',
    name: 'Vulnerable and Outdated Components',
    description:
      'Components run with the same privileges as the application itself, so flaws in any component can result in serious impact. Outdated components with known vulnerabilities expose systems to automated exploitation.',
    cwes: ['CWE-1104'],
    remediationOverview:
      'Remove unused dependencies, unnecessary features, components, files, and documentation. Continuously inventory versions of client-side and server-side components and their dependencies.',
  },
  'A07:2021': {
    id: 'A07:2021',
    title: 'A07:2021 - Identification and Authentication Failures',
    name: 'Identification and Authentication Failures',
    description:
      'Confirmation of the user identity, authentication, and session management is critical to protect against authentication-related attacks such as credential stuffing, brute force, and session hijacking.',
    cwes: ['CWE-287', 'CWE-384', 'CWE-613'],
    remediationOverview:
      'Where possible, implement multi-factor authentication. Do not ship with default credentials. Implement weak password checks. Align password length, complexity, and rotation policies with NIST 800-63b guidelines. Use secure session managers with rotation.',
  },
  'A08:2021': {
    id: 'A08:2021',
    title: 'A08:2021 - Software and Data Integrity Failures',
    name: 'Software and Data Integrity Failures',
    description:
      'Relates to code and infrastructure that does not protect against integrity violations, including insecure CI/CD pipelines, untrusted CDN imports, and insecure deserialization flaws.',
    cwes: ['CWE-502', 'CWE-829'],
    remediationOverview:
      'Use digital signatures or similar mechanisms to verify software or data is from the expected source. Ensure untrusted objects are not deserialized without prior verification or signing.',
  },
  'A09:2021': {
    id: 'A09:2021',
    title: 'A09:2021 - Security Logging and Monitoring Failures',
    name: 'Security Logging and Monitoring Failures',
    description:
      'Insufficient logging, detection, monitoring, and active response allows attacks to continue undetected. Auditable events such as logins, failed logins, and high-value transactions must be logged with sufficient context.',
    cwes: ['CWE-778', 'CWE-117'],
    remediationOverview:
      'Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts. Ensure logs are formatted to prevent log injection.',
  },
  'A10:2021': {
    id: 'A10:2021',
    title: 'A10:2021 - Server-Side Request Forgery (SSRF)',
    name: 'Server-Side Request Forgery (SSRF)',
    description:
      'SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.',
    cwes: ['CWE-918'],
    remediationOverview:
      'Enforce positive allowlists for schemes and destinations. Block requests to internal, loopback, and private IP ranges. Disable HTTP redirections on server-side requests.',
  },
};
