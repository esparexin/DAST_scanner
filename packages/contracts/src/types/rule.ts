import type {
  DetectionCategory,
  DetectionType,
  Severity,
  Confidence,
} from '../enums.js';

export interface ISecurityRule {
  id: string;
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
}
