import type { ISecurityRule } from './rule.js';

export interface SecurityIntelligencePackage {
  packageVersion: string;
  generatedAt: string;
  rules: ISecurityRule[];
  payloads: Array<{
    id: string;
    version: string;
    status: string;
    category: string;
    template: { raw: string; [key: string]: unknown };
    detection: { strategy: string; [key: string]: unknown };
    verification: { strategy: string; [key: string]: unknown };
    [key: string]: unknown;
  }>;
  taxonomies?: {
    cwe?: string[];
    owasp?: string[];
    wstg?: string[];
    asvs?: string[];
  };
  metadata?: Record<string, unknown>;
}

export interface SecurityIntelligenceManifest {
  packageVersion: string;
  generatedAt: string;
  ruleCount: number;
  ruleIds: string[];
  payloadCount: number;
  payloadIds: string[];
  rulesHash: string;
  payloadsHash: string;
  packageHash: string;
  signature: string;
}
