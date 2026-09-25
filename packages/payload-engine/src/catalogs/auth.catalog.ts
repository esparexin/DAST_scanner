import type { IPayloadDefinition } from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

export const AUTH_CATALOG: IPayloadDefinition[] = [
  {
    id: 'PL-AUTH-JWT-001',
    name: 'JWT None-Algorithm Mutated Token',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.AUTHENTICATION,
    subcategory: 'jwt-algorithm-confusion',
    description: 'Constructs an unsigned JWT token with alg: none to test signature verification bypass.',
    safetyLevel: 'SAFE',
    template: {
      raw: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{{VALUE}}.',
      supportedTransformations: ['NONE'],
    },
    applicability: {
      parameterLocations: ['header'],
      parameterTypes: ['string'],
      targetContexts: ['HEADER_VALUE'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'DIFFERENTIAL_STATUS',
      expectedStatusCodes: [200, 201],
    },
    verification: {
      strategy: 'STATUS_CODE_STABILITY',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-287', 'CWE-345'],
      owaspTop10: ['A07:2021'],
      owaspApiSecurity: ['API2:2023'],
      wstg: ['WSTG-ATHN-01'],
      asvs: ['V3.5.2'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      cvssScore: 9.1,
      portswiggerTopic: 'jwt',
    },
    remediation: {
      concept: 'Enforce cryptographic signature validation and whitelist algorithms.',
      guidance: 'Configure JWT verification to reject algorithm "none" explicitly and verify signature before claims.',
      defenseInDepth: ['Enforce short-lived token expirations and token revocation checks.'],
    },
  },
];
