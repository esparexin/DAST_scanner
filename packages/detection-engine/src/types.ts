import type { SecureHttpClient } from '@securityscan/http-client';
import type {
  ISecurityRule,
  Severity,
  Confidence,
  DetectionCategory,
  IEndpoint,
} from '@securityscan/contracts';

export interface CheckContext {
  scanId: string;
  targetId: string;
  projectId: string;
  httpClient: SecureHttpClient;
  endpoint: IEndpoint;
  baseUrl: string;
}

export interface CheckResult {
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
  apiOwasp: string[];
  references: string[];
  evidence: {
    request: { method: string; url: string; headers: Record<string, string>; body?: string };
    response: { statusCode: number; headers: Record<string, string>; body?: string; responseTime: number };
  };
}

export interface SecurityCheck {
  rule: ISecurityRule;
  run(context: CheckContext): Promise<CheckResult[]>;
}
