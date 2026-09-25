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
  owasp: string[];
  apiOwasp: string[];
  cwe: string[];
  wstg: string[];
  portswigger: string[];
  remediation: string;
  references: string[];
  enabled: boolean;
  tags: string[];
}
