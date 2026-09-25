import type { HttpMethod } from '../enums.js';

export interface IHttpRequest {
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeout?: number;
  followRedirects?: boolean;
  maxRedirects?: number;
  maxResponseSize?: number;
}

export interface IHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  responseTime: number;
  url: string;
  redirectChain?: string[];
  size: number;
}

export interface IHttpClientConfig {
  baseHeaders?: Record<string, string>;
  timeout?: number;
  followRedirects?: boolean;
  maxRedirects?: number;
  maxResponseSize?: number;
  userAgent?: string;
}
