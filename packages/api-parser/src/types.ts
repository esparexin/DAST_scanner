import { ApiType, ApiSchemaFormat, HttpMethod } from '@securityscan/contracts';

export interface NormalizedApiEndpoint {
  path: string;
  method: HttpMethod;
  operationId?: string;
  summary?: string;
  parameters: Array<{
    name: string;
    location: 'query' | 'path' | 'header' | 'body' | 'cookie';
    required: boolean;
    type: string;
  }>;
  declaredResponseProperties?: Record<string, string[]>; // statusCode -> property names
  security: string[];
}

export interface UnifiedApiDefinition {
  title: string;
  version: string;
  type: ApiType;
  format: ApiSchemaFormat;
  baseUrl: string;
  endpoints: NormalizedApiEndpoint[];
  rawSchema: string;
  valid: boolean;
  errors: string[];
}
