import type { HttpMethod } from '../enums.js';

export interface IEndpoint {
  id: string;
  scanId: string;
  targetId: string;
  projectId: string;
  method: HttpMethod;
  url: string;
  path: string;
  parameters: IEndpointParameter[];
  headers: Record<string, string>;
  requestContentType?: string;
  responseContentType?: string;
  statusCode?: number;
  requiresAuth: boolean;
  discoverySource: EndpointDiscoverySource;
  apiId?: string;
  schemaOperationId?: string;
  createdAt: Date;
}

export interface IEndpointParameter {
  name: string;
  location: 'query' | 'path' | 'header' | 'body' | 'cookie';
  type?: string;
  required?: boolean;
  example?: string;
}

export type EndpointDiscoverySource =
  | 'crawler'
  | 'sitemap'
  | 'robots'
  | 'javascript'
  | 'openapi'
  | 'graphql'
  | 'manual'
  | 'form'
  | 'link';
