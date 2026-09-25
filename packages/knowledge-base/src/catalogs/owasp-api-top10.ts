export interface OwaspApiTop10Item {
  id: string; // e.g. 'API1:2023'
  title: string;
  name: string;
  description: string;
  cwes: string[];
  remediationOverview: string;
}

export const OWASP_API_TOP_10_2023: Record<string, OwaspApiTop10Item> = {
  'API1:2023': {
    id: 'API1:2023',
    title: 'API1:2023 - Broken Object Level Authorization (BOLA)',
    name: 'Broken Object Level Authorization',
    description:
      'APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface for Object Level Access Control issues. Object level authorization checks should be considered in every function that accesses a data source using an input from the user.',
    cwes: ['CWE-639', 'CWE-285'],
    remediationOverview:
      'Implement a proper authorization mechanism that relies on the user policies and hierarchy. Check if the logged-in user has access to perform the requested action on the target record for every data operation.',
  },
  'API2:2023': {
    id: 'API2:2023',
    title: 'API2:2023 - Broken Authentication',
    name: 'Broken Authentication',
    description:
      'Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws to assume other user identities temporarily or permanently.',
    cwes: ['CWE-287', 'CWE-384'],
    remediationOverview:
      'Know all authentication flows. Understand OAuth/OIDC implementation details. Enforce token validation and expiration checks. Implement rate limiting on sensitive authentication endpoints.',
  },
  'API3:2023': {
    id: 'API3:2023',
    title: 'API3:2023 - Broken Object Property Level Authorization',
    name: 'Broken Object Property Level Authorization',
    description:
      'Covers Excessive Data Exposure and Mass Assignment flaws. Attackers exploit lack of property-level authorization to read sensitive property values or modify properties they should not be allowed to change.',
    cwes: ['CWE-200', 'CWE-915'],
    remediationOverview:
      'Never rely on the client to filter data. Avoid using generic functions such as bind() that automatically map client input variables to internal object properties. Whitelist allowed properties explicitly.',
  },
  'API4:2023': {
    id: 'API4:2023',
    title: 'API4:2023 - Unrestricted Resource Consumption',
    name: 'Unrestricted Resource Consumption',
    description:
      'Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage. APIs without limits on client requests or resource allocation are vulnerable to Denial of Service or excessive billing.',
    cwes: ['CWE-770', 'CWE-400'],
    remediationOverview:
      'Implement limits on execution timeouts, maximum allocated memory, maximum number of operations per request, maximum request payload size, and paging boundaries.',
  },
  'API5:2023': {
    id: 'API5:2023',
    title: 'API5:2023 - Broken Function Level Authorization (BFLA)',
    name: 'Broken Function Level Authorization',
    description:
      'Complex access control policies with different hierarchies, groups, and roles, and an unclear separation between administrative and regular functions tend to lead to authorization flaws.',
    cwes: ['CWE-285'],
    remediationOverview:
      'Enforce strict role-based access control. Deny all access by default. Ensure administrative endpoints are isolated and check privileges on every incoming request.',
  },
  'API6:2023': {
    id: 'API6:2023',
    title: 'API6:2023 - Unrestricted Access to Sensitive Business Flows',
    name: 'Unrestricted Access to Sensitive Business Flows',
    description:
      'APIs vulnerable to this risk expose a business flow - such as buying a ticket, posting a review, or issuing reservations - without restricting access velocity, enabling automated abuse.',
    cwes: ['CWE-799'],
    remediationOverview:
      'Identify critical business flows. Implement human verification mechanisms, velocity checks, device fingerprinting, and behavioral sequence validation.',
  },
  'API7:2023': {
    id: 'API7:2023',
    title: 'API7:2023 - Server Side Request Forgery',
    name: 'Server Side Request Forgery',
    description:
      'SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URI. This enables attackers to coerce the application to send requests to unexpected destinations, bypassing perimeter firewalls.',
    cwes: ['CWE-918'],
    remediationOverview:
      'Isolate the resource fetching mechanism in a separate network. Validate and sanitize all client-supplied input data against an explicit destination allowlist.',
  },
  'API8:2023': {
    id: 'API8:2023',
    title: 'API8:2023 - Security Misconfiguration',
    name: 'Security Misconfiguration',
    description:
      'APIs and systems supporting them often have complex configurations. Common misconfigurations include unpatched flaws, unneeded features enabled, missing security headers, permissive CORS, and verbose error traces.',
    cwes: ['CWE-16', 'CWE-209', 'CWE-942', 'CWE-693'],
    remediationOverview:
      'Establish automated configuration review processes. Review and update CORS policies, send defensive security headers, and disable verbose stack traces in production responses.',
  },
  'API9:2023': {
    id: 'API9:2023',
    title: 'API9:2023 - Improper Inventory Management',
    name: 'Improper Inventory Management',
    description:
      'APIs tend to expose more endpoints than traditional web applications. Outdated API versions (shadow/zombie APIs) often have unpatched vulnerabilities and lack modern security controls.',
    cwes: ['CWE-1059'],
    remediationOverview:
      'Inventory all API hosts and endpoints. Document all API aspects including authentication, parameters, and retirement schedules. Retire old versions once superseded.',
  },
  'API10:2023': {
    id: 'API10:2023',
    title: 'API10:2023 - Unsafe Consumption of APIs',
    name: 'Unsafe Consumption of APIs',
    description:
      'Developers tend to trust data received from third-party APIs more than user input. Blindly trusting third-party API data can lead to injection, SSRF, or improper data handling.',
    cwes: ['CWE-20'],
    remediationOverview:
      'Always validate and sanitize data received from third-party APIs. Enforce TLS for all third-party interactions. Implement explicit timeouts and connection limits.',
  },
};
