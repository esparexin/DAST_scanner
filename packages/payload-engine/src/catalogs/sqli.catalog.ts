import type { IPayloadDefinition } from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

export const SQLI_CATALOG: IPayloadDefinition[] = [
  {
    id: 'PL-SQLI-ERR-001',
    name: 'SQL Syntax Error Disruption (Single Quote)',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'error-based',
    description: 'Injects unclosed single quote to disrupt SQL interpreter grammar and provoke syntax error leaks.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: "'\"",
      supportedTransformations: ['NONE', 'URL_ENCODE', 'DOUBLE_URL_ENCODE', 'WHITESPACE_ALTERNATIVE'],
    },
    applicability: {
      parameterLocations: ['query', 'body', 'path'],
      parameterTypes: ['string', 'integer'],
      targetContexts: ['ANY', 'SQL_CLAUSE'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'ERROR_SIGNATURE',
      errorSignatures: [
        'syntax error at or near',
        'invalid input syntax for',
        'you have an error in your sql syntax',
        'warning: mysql_',
        'unrecognized token:',
        'sqlite3::sqlexception',
        'unclosed quotation mark after the character string',
        'ora-01756: quoted string not properly terminated',
      ],
    },
    verification: {
      strategy: 'REPLAY_PROBE_CONFIRMATION',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: ['API8:2023'],
      wstg: ['WSTG-INPV-05'],
      asvs: ['V5.3.4', 'V5.3.5'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssScore: 9.8,
      portswiggerTopic: 'sql-injection',
    },
    remediation: {
      concept: 'Enforce parameterized queries or ORM abstraction.',
      guidance: 'Ensure all dynamic parameters are passed via prepared statements with bound parameters.',
      defenseInDepth: ['Disable verbose database error dumps in production environments.'],
    },
  },
  {
    id: 'PL-SQLI-NUM-002',
    name: 'SQL Numeric Arithmetic Identity (10-0)',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'boolean-arithmetic',
    description: 'Evaluates numeric parameter arithmetic resolution without injecting quotes (detecting unparameterized integer interpolation).',
    safetyLevel: 'SAFE',
    template: {
      raw: '{{VALUE}}-0',
      supportedTransformations: ['NONE', 'URL_ENCODE'],
    },
    applicability: {
      parameterLocations: ['query', 'path'],
      parameterTypes: ['integer', 'number'],
      targetContexts: ['ANY', 'SQL_CLAUSE'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'DIFFERENTIAL_STATUS',
      expectedStatusCodes: [200],
    },
    verification: {
      strategy: 'REPLAY_PROBE_CONFIRMATION',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-89'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: ['API8:2023'],
      wstg: ['WSTG-INPV-05'],
      asvs: ['V5.3.4'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssScore: 9.8,
    },
    remediation: {
      concept: 'Cast or parameterize numeric input server-side.',
      guidance: 'Parse and validate that numeric identifiers are strictly integer types prior to SQL concatenation.',
      defenseInDepth: ['Use strongly typed DTOs.'],
    },
  },
];
