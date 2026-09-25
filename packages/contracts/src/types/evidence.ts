export interface IEvidence {
  id: string;
  findingId: string;
  scanId: string;
  request: IRedactedHttpRequest;
  response: IRedactedHttpResponse;
  endpoint: string;
  parameter?: string;
  authContext: string;
  comparisonResults?: IComparisonResult[];
  timestamp: Date;
  relevantHeaders: Record<string, string>;
  relevantResponseData: string;
  createdAt: Date;
}

export interface IRedactedHttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface IRedactedHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body?: string;
  responseTime: number;
}

export interface IComparisonResult {
  label: string;
  expected: string;
  actual: string;
  match: boolean;
}

export interface IProofOfConcept {
  id: string;
  findingId: string;
  summary: string;
  preconditions: string[];
  steps: IReproductionStep[];
  request: IRedactedHttpRequest;
  response: IRedactedHttpResponse;
  evidence: IEvidence;
  expectedBehavior: string;
  observedBehavior: string;
  remediation: string;
  createdAt: Date;
}

export interface IReproductionStep {
  order: number;
  description: string;
  request?: IRedactedHttpRequest;
  response?: IRedactedHttpResponse;
}
