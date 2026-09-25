import type { IPayloadDefinition } from '../types/payload-definition.js';
import { DetectionCategory } from '@securityscan/contracts';

export const TRAVERSAL_CATALOG: IPayloadDefinition[] = [
  {
    id: 'PL-PT-UNIX-001',
    name: 'Unix Canonical Path Traversal (etc/passwd)',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.PATH_TRAVERSAL,
    subcategory: 'unix-traversal',
    description: 'Probes for directory traversal using relative path sequences targeting the standard Unix passwd file.',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: {
      raw: '../../../../etc/passwd',
      supportedTransformations: ['NONE', 'URL_ENCODE', 'DOUBLE_URL_ENCODE', 'NULL_BYTE_PREFIX'],
    },
    applicability: {
      parameterLocations: ['query', 'body', 'path'],
      parameterTypes: ['string', 'file'],
      targetContexts: ['ANY', 'FILE_PATH'],
      protocols: ['HTTP', 'HTTPS'],
      serverEngines: ['unix'],
    },
    detection: {
      strategy: 'ERROR_SIGNATURE',
      errorSignatures: [
        'root:x:0:0:',
        'root:*:0:0:',
        '/bin/bash',
        '/bin/sh',
      ],
    },
    verification: {
      strategy: 'REPLAY_PROBE_CONFIRMATION',
      replayAttemptsRequired: 2,
    },
    references: {
      cwe: ['CWE-22'],
      owaspTop10: ['A01:2021'],
      owaspApiSecurity: [],
      wstg: ['WSTG-ATHZ-01'],
      asvs: ['V12.3.1'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      cvssScore: 7.5,
      portswiggerTopic: 'path-traversal',
    },
    remediation: {
      concept: 'Use path canonicalization and index allowlists.',
      guidance: 'Resolve user-supplied file requests to an absolute path and verify the canonical path begins with the intended root directory.',
      defenseInDepth: ['Run web services in a chroot jail or container with read-only root filesystems.'],
    },
  },
];
