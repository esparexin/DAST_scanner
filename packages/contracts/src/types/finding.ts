import type {
  Severity,
  Confidence,
  FindingStatus,
  DetectionCategory,
} from '../enums.js';

export interface IFinding {
  id: string;
  scanId: string;
  projectId: string;
  targetId: string;
  ruleId: string;
  title: string;
  description: string;
  impact: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  category: DetectionCategory;
  endpoint: string;
  method: string;
  parameter?: string;
  evidenceIds: string[];
  pocId?: string;
  remediation: string;
  cwe: string[];
  owasp: string[];
  apiOwasp: string[];
  wstg: string[];
  asvs: string[];
  cvssVector?: string;
  cvssScore?: number;
  references: string[];
  deduplicationKey: string;
  firstDetectedAt: Date;
  lastDetectedAt: Date;
  verifiedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface ICreateFinding {
  scanId: string;
  projectId: string;
  targetId: string;
  ruleId: string;
  title: string;
  description: string;
  impact: string;
  severity: Severity;
  confidence: Confidence;
  category: DetectionCategory;
  endpoint: string;
  method: string;
  parameter?: string;
  remediation: string;
  cwe: string[];
  owasp: string[];
  apiOwasp?: string[];
  wstg?: string[];
  asvs?: string[];
  cvssVector?: string;
  cvssScore?: number;
  references?: string[];
}
