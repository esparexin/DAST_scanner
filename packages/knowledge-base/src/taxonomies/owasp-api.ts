export interface OwaspApiItem {
  id: string;
  year: 2023;
  code: string;
  name: string;
  description: string;
}

export const OWASP_API_SECURITY_2023: Record<string, OwaspApiItem> = {
  'API1:2023': {
    id: 'API1:2023',
    year: 2023,
    code: 'API1',
    name: 'Broken Object Level Authorization',
    description: 'APIs expose endpoints that handle object identifiers, creating a wide level access control attack surface.',
  },
  'API2:2023': {
    id: 'API2:2023',
    year: 2023,
    code: 'API2',
    name: 'Broken Authentication',
    description: 'Authentication mechanisms are incorrectly implemented, allowing attackers to compromise authentication tokens.',
  },
  'API3:2023': {
    id: 'API3:2023',
    year: 2023,
    code: 'API3',
    name: 'Broken Object Property Level Authorization',
    description: 'Lack of or improper authorization validation at the object property level (mass assignment, excessive data exposure).',
  },
  'API4:2023': {
    id: 'API4:2023',
    year: 2023,
    code: 'API4',
    name: 'Unrestricted Resource Consumption',
    description: 'API does not set proper limits for resource size, request rate, execution timeouts, or memory limits.',
  },
  'API5:2023': {
    id: 'API5:2023',
    year: 2023,
    code: 'API5',
    name: 'Broken Function Level Authorization',
    description: 'Complex access control policies with different roles allow users to access administrative or unauthorized functions.',
  },
  'API6:2023': {
    id: 'API6:2023',
    year: 2023,
    code: 'API6',
    name: 'Unrestricted Access to Sensitive Business Flows',
    description: 'APIs expose business flows (purchasing, booking, reset tokens) without mitigating automated excessive requests.',
  },
  'API7:2023': {
    id: 'API7:2023',
    year: 2023,
    code: 'API7',
    name: 'Server Side Request Forgery',
    description: 'API processes external URLs provided by client without proper input validation.',
  },
  'API8:2023': {
    id: 'API8:2023',
    year: 2023,
    code: 'API8',
    name: 'Security Misconfiguration',
    description: 'Improperly configured HTTP headers, open CORS, verbose error messages, or unpatched systems.',
  },
  'API9:2023': {
    id: 'API9:2023',
    year: 2023,
    code: 'API9',
    name: 'Improper Inventory Management',
    description: 'Exposing deprecated API versions, undocumented debug endpoints, or legacy endpoints without authorization controls.',
  },
  'API10:2023': {
    id: 'API10:2023',
    year: 2023,
    code: 'API10',
    name: 'Unsafe Consumption of APIs',
    description: 'Developers trust data received from third-party APIs more than user input, adopting weak security standards.',
  },
};
