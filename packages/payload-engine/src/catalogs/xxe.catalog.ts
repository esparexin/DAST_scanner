import type { IPayloadDefinition } from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

export const XXE_CATALOG: IPayloadDefinition[] = [
  {
    id: 'PL-XXE-DECL-001',
    name: 'XXE Entity Declaration Canary',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'xxe-entity',
    description:
      'Injects a benign XML entity declaration that references a non-existent local file. If the parser processes the entity, it confirms external entity expansion is enabled.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxecanary "canaryvalue">]><root>&xxecanary;</root>',
      supportedTransformations: ['NONE'],
    },
    applicability: {
      parameterLocations: ['body'],
      parameterTypes: ['xml', 'string'],
      targetContexts: ['XML_VALUE', 'ANY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'ERROR_SIGNATURE',
      errorSignatures: ['canaryvalue'],
    },
    verification: {
      strategy: 'REPLAY_PROBE_CONFIRMATION',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-611'],
      owaspTop10: ['A05:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-INPV-07'],
      asvs: ['V5.5.2'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L',
      cvssScore: 8.2,
      portswiggerTopic: 'xxe',
    },
    remediation: {
      concept: 'Disable external entity processing in XML parsers.',
      guidance:
        'Configure XML parsers with disallow-doctype-decl=true or disable external general and parameter entities. Use JSON instead of XML where possible.',
      defenseInDepth: [
        'Validate and sanitize XML input against an XSD schema.',
        'Use defused XML parsing libraries (e.g., defusedxml for Python, secure-xml-parser for Node.js).',
      ],
    },
  },
  {
    id: 'PL-XXE-DECL-002',
    name: 'XXE Parameter Entity Probe',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'xxe-parameter-entity',
    description:
      'Tests for parameter entity expansion support which can lead to blind XXE and data exfiltration.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxeparam "test">%xxeparam;]><root>probe</root>',
      supportedTransformations: ['NONE'],
    },
    applicability: {
      parameterLocations: ['body'],
      parameterTypes: ['xml', 'string'],
      targetContexts: ['XML_VALUE', 'ANY'],
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
      cwe: ['CWE-611'],
      owaspTop10: ['A05:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-INPV-07'],
      asvs: ['V5.5.2'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L',
      cvssScore: 8.2,
    },
    remediation: {
      concept: 'Disable DTD processing entirely.',
      guidance:
        'Set XMLReader features to disallow DTDs. Migrate XML endpoints to JSON where feasible.',
      defenseInDepth: ['Network-level egress filtering to block SSRF via XXE.'],
    },
  },
];
