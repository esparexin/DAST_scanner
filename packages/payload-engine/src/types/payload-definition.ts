import { DetectionCategory, Severity, Confidence } from '@securityscan/contracts';

export type PayloadSafetyLevel = 'SAFE' | 'BOUNDED_ACTIVE' | 'POTENTIALLY_DISRUPTIVE';

export type PayloadStatus = 'DRAFT' | 'ACTIVE' | 'DEPRECATED' | 'DISABLED' | 'ARCHIVED';

export type ApplicableParameterType =
  | 'string'
  | 'integer'
  | 'number'
  | 'boolean'
  | 'uuid'
  | 'email'
  | 'url'
  | 'json'
  | 'array'
  | 'file';

export type ParameterLocation = 'query' | 'body' | 'path' | 'header' | 'cookie';

export type TargetReflectionContext =
  | 'ANY'
  | 'HTML_BODY'
  | 'HTML_ATTRIBUTE'
  | 'JAVASCRIPT_BLOCK'
  | 'JSON_VALUE'
  | 'HEADER_VALUE'
  | 'SQL_CLAUSE'
  | 'COMMAND_ARGUMENT'
  | 'FILE_PATH';

export type TransformationType =
  | 'NONE'
  | 'URL_ENCODE'
  | 'DOUBLE_URL_ENCODE'
  | 'HTML_ENTITY'
  | 'JSON_ESCAPE'
  | 'WHITESPACE_ALTERNATIVE'
  | 'CASE_VARIATION'
  | 'NULL_BYTE_PREFIX'
  | 'HPP_POLLUTION';

export type DetectionStrategy =
  | 'ERROR_SIGNATURE'
  | 'CANARY_REFLECTION'
  | 'DIFFERENTIAL_STATUS'
  | 'DIFFERENTIAL_LENGTH'
  | 'TIME_DELAY_SAFE'
  | 'OUT_OF_BAND_SAFE';

export type VerificationStrategy =
  | 'REPLAY_PROBE_CONFIRMATION'
  | 'INVERSE_PROBE_CONFIRMATION'
  | 'TOKEN_EQUIVALENCE'
  | 'STATUS_CODE_STABILITY';

export interface IPayloadRegressionTest {
  targetFixtureId: string;
  expectedOutcome: 'VULNERABLE' | 'SAFE' | 'REJECTED';
  description: string;
}

export interface IPayloadDefinition {
  id: string;
  name: string;
  version: string;
  status: PayloadStatus;
  category: DetectionCategory;
  subcategory: string;
  description: string;
  safetyLevel: PayloadSafetyLevel;

  // The abstract template (supports canary placeholders: {{CANARY}}, {{PARAM}}, {{VALUE}})
  template: {
    raw: string;
    canaryPrefix?: string;
    defaultCanaryType?: 'ALPHANUMERIC' | 'NUMERIC' | 'RANDOM_TAG';
    supportedTransformations: TransformationType[];
  };

  // Context matching rules (Is this payload appropriate for this parameter?)
  applicability: {
    parameterLocations: ParameterLocation[];
    parameterTypes: ApplicableParameterType[];
    targetContexts: TargetReflectionContext[];
    protocols: Array<'HTTP' | 'HTTPS' | 'WS' | 'WSS' | 'GRPC'>;
    contentTypes?: string[];
    serverEngines?: string[]; // e.g. ['unix', 'windows', 'postgres', 'mysql', 'sqlite']
    prerequisites?: string[];
  };

  // Detection and Verification specification
  detection: {
    strategy: DetectionStrategy;
    errorSignatures?: string[];
    expectedStatusCodes?: number[];
    bodyIndicators?: string[];
  };

  verification: {
    strategy: VerificationStrategy;
    replayAttemptsRequired: number;
    differentialComparisonTolerance?: number;
  };

  // Standards and Security Taxonomy References
  references: {
    cwe: string[];
    owaspTop10: string[];
    owaspApiSecurity: string[];
    wstg: string[];
    asvs: string[];
    cvssVector?: string;
    cvssScore?: number;
    portswiggerTopic?: string;
  };

  remediation: {
    summary: string;
    guidance: string;
    defenseInDepth: string[];
  };

  regressionTests?: IPayloadRegressionTest[];
}
