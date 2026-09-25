import type { ApiType, ApiSchemaFormat } from '../enums.js';

export interface IApi {
  id: string;
  projectId: string;
  targetId: string;
  name: string;
  type: ApiType;
  baseUrl: string;
  version?: string;
  description?: string;
  schemaId?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface IApiSchema {
  id: string;
  apiId: string;
  projectId: string;
  format: ApiSchemaFormat;
  version?: string;
  content: string;
  parsed: boolean;
  valid: boolean;
  validationErrors?: string[];
  endpointCount?: number;
  importedAt: Date;
  createdAt: Date;
}

export interface ICreateApi {
  projectId: string;
  targetId: string;
  name: string;
  type: ApiType;
  baseUrl: string;
  version?: string;
  description?: string;
}

export interface IImportApiSchema {
  apiId: string;
  format: ApiSchemaFormat;
  content: string;
}
