import type { IPayloadDefinition } from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

export const SSTI_CATALOG: IPayloadDefinition[] = [
  {
    id: 'PL-SSTI-MATH-001',
    name: 'SSTI Arithmetic Canary (7*7=49)',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'ssti-arithmetic',
    description:
      'Injects a benign arithmetic expression canary ({{7*7}}) to detect server-side template interpretation. If the response contains "49" instead of the literal "{{7*7}}", the template engine evaluates user input.',
    safetyLevel: 'SAFE',
    template: {
      raw: '{{7*7}}',
      supportedTransformations: ['NONE', 'URL_ENCODE'],
    },
    applicability: {
      parameterLocations: ['query', 'body', 'path'],
      parameterTypes: ['string'],
      targetContexts: ['ANY', 'HTML_BODY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'ERROR_SIGNATURE',
      errorSignatures: ['49'],
    },
    verification: {
      strategy: 'REPLAY_PROBE_CONFIRMATION',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-1336'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-INPV-18'],
      asvs: ['V5.2.4'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssScore: 9.8,
      portswiggerTopic: 'server-side-template-injection',
    },
    remediation: {
      concept: 'Never pass user input as template source.',
      guidance:
        'Use template engines in sandboxed mode. Pass user data as template variables, never as template strings that get compiled.',
      defenseInDepth: [
        'Use logic-less template engines (Mustache) for user-facing content.',
        'Restrict template engine globals and built-in functions.',
      ],
    },
  },
  {
    id: 'PL-SSTI-MATH-002',
    name: 'SSTI Arithmetic Canary Jinja2/Twig (${7*7})',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'ssti-arithmetic',
    description:
      'Injects ${7*7} syntax used by Jinja2, Twig, and Freemarker to detect SSTI via arithmetic evaluation.',
    safetyLevel: 'SAFE',
    template: {
      raw: '${7*7}',
      supportedTransformations: ['NONE', 'URL_ENCODE'],
    },
    applicability: {
      parameterLocations: ['query', 'body', 'path'],
      parameterTypes: ['string'],
      targetContexts: ['ANY', 'HTML_BODY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'ERROR_SIGNATURE',
      errorSignatures: ['49'],
    },
    verification: {
      strategy: 'REPLAY_PROBE_CONFIRMATION',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-1336'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-INPV-18'],
      asvs: ['V5.2.4'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssScore: 9.8,
    },
    remediation: {
      concept: 'Isolate template compilation from user input.',
      guidance:
        'Pre-compile templates at build time. Never use user strings in template constructor or render source arguments.',
      defenseInDepth: ['Audit template engine configuration for auto-escape directives.'],
    },
  },
];
