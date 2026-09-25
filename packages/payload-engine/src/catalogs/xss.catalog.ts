import type { IPayloadDefinition } from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

export const XSS_CATALOG: IPayloadDefinition[] = [
  {
    id: 'PL-XSS-TAG-001',
    name: 'Reflected HTML Tag Canary Probe',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.XSS,
    subcategory: 'reflected-html',
    description: 'Injects unique benign random alphanumeric tag to detect unescaped HTML reflection in body context.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: '<{{CANARY}}>',
      canaryPrefix: 'xsscanary',
      defaultCanaryType: 'RANDOM_TAG',
      supportedTransformations: ['NONE', 'URL_ENCODE', 'HTML_ENTITY'],
    },
    applicability: {
      parameterLocations: ['query', 'path', 'body'],
      parameterTypes: ['string'],
      targetContexts: ['ANY', 'HTML_BODY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'CANARY_REFLECTION',
    },
    verification: {
      strategy: 'TOKEN_EQUIVALENCE',
      replayAttemptsRequired: 1,
    },
    references: {
      cwe: ['CWE-79'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-INPV-01'],
      asvs: ['V5.3.1', 'V5.3.3'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      cvssScore: 6.1,
      portswiggerTopic: 'cross-site-scripting',
    },
    remediation: {
      concept: 'Context-aware HTML output encoding.',
      guidance: 'Sanitize and convert user-supplied strings into HTML entities (&lt;, &gt;, &quot;, &#x27;) before rendering in markup.',
      defenseInDepth: ['Deploy Content-Security-Policy with strict script-src and default-src directives.'],
    },
  },
  {
    id: 'PL-XSS-ATTR-002',
    name: 'Reflected HTML Attribute Breakout Canary',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.XSS,
    subcategory: 'reflected-attribute',
    description: 'Injects quote escape and benign attribute canary to test for attribute context reflection vulnerabilities.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: '" {{CANARY}}="1',
      canaryPrefix: 'attrcanary',
      defaultCanaryType: 'ALPHANUMERIC',
      supportedTransformations: ['NONE', 'URL_ENCODE'],
    },
    applicability: {
      parameterLocations: ['query', 'body'],
      parameterTypes: ['string'],
      targetContexts: ['HTML_ATTRIBUTE', 'ANY'],
      protocols: ['HTTP', 'HTTPS'],
    },
    detection: {
      strategy: 'CANARY_REFLECTION',
    },
    verification: {
      strategy: 'TOKEN_EQUIVALENCE',
      replayAttemptsRequired: 1,
    },
    references: {
      cwe: ['CWE-79'],
      owaspTop10: ['A03:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-INPV-01'],
      asvs: ['V5.3.1'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      cvssScore: 6.1,
    },
    remediation: {
      concept: 'HTML attribute encoding.',
      guidance: 'Ensure all values rendered inside HTML tag attributes are strictly attribute-encoded.',
      defenseInDepth: ['Quote all HTML attributes using double quotes.'],
    },
  },
];
