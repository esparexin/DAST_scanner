import type {
  DetectionCategory,
  DetectionType,
  Severity,
  Confidence,
} from '../enums.js';

export type RuleStatus = 'DRAFT' | 'ACTIVE' | 'DEPRECATED' | 'DISABLED';

export interface ISecurityRule {
  id: string;
  ruleVersion?: string;
  contentHash?: string;
  status?: RuleStatus;
  name: string;
  description: string;
  category: DetectionCategory;
  type: DetectionType;
  severity: Severity;
  confidence: Confidence;
  cvssVector?: string;
  cvssScore?: number;
  owasp: string[];
  apiOwasp: string[];
  cwe: string[];
  wstg: string[];
  asvs: string[];
  portswigger: string[];
  remediation: string;
  references: string[];
  enabled: boolean;
  tags: string[];
  createdAt?: string;
  updatedAt?: string;
  deprecatedAt?: string;
}
