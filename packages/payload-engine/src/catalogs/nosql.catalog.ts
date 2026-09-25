import type { IPayloadDefinition } from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

export const NOSQL_CATALOG: IPayloadDefinition[] = [
  {
    id: 'PL-NOSQL-OBJ-001',
    name: 'NoSQL Object Injection (MongoDB $ne Operator)',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'nosql-operator',
    description:
      'Injects MongoDB query operator $ne to test for NoSQL operator injection in JSON body parameters.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: '{"$ne": ""}',
      supportedTransformations: ['NONE', 'JSON_ESCAPE'],
    },
    applicability: {
      parameterLocations: ['body'],
      parameterTypes: ['string', 'json'],
      targetContexts: ['JSON_VALUE', 'ANY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'DIFFERENTIAL_STATUS',
      expectedStatusCodes: [200],
    },
    verification: {
      strategy: 'STATUS_CODE_STABILITY',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-943'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: ['API8:2023'],
      wstg: ['WSTG-INPV-05'],
      asvs: ['V5.3.4'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      cvssScore: 9.1,
    },
    remediation: {
      concept: 'Sanitize query operators from user input.',
      guidance:
        'Strip or reject any keys beginning with $ from user-supplied JSON before passing to MongoDB query constructors. Use schema-validated DTOs.',
      defenseInDepth: [
        'Use allowlist-based input validation with Zod or Joi.',
        'Enable MongoDB query logging to detect operator injection attempts.',
      ],
    },
  },
  {
    id: 'PL-NOSQL-OBJ-002',
    name: 'NoSQL Object Injection (MongoDB $gt Operator)',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'nosql-operator',
    description:
      'Injects MongoDB $gt operator to test for authentication bypass via always-true conditions.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: '{"$gt": ""}',
      supportedTransformations: ['NONE', 'JSON_ESCAPE'],
    },
    applicability: {
      parameterLocations: ['body'],
      parameterTypes: ['string', 'json'],
      targetContexts: ['JSON_VALUE', 'ANY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'DIFFERENTIAL_STATUS',
      expectedStatusCodes: [200],
    },
    verification: {
      strategy: 'STATUS_CODE_STABILITY',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-943'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: ['API8:2023'],
      wstg: ['WSTG-INPV-05'],
      asvs: ['V5.3.4'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      cvssScore: 9.1,
    },
    remediation: {
      concept: 'Reject MongoDB operators in user-controlled fields.',
      guidance:
        'Validate all input against a strict schema. Convert JSON body fields to primitive types before database query construction.',
      defenseInDepth: ['Use Mongoose strict mode or explicit casting.'],
    },
  },
];
