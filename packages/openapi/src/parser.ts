import YAML from 'yaml';
import { HttpMethod, ApiSchemaFormat } from '@securityscan/contracts';
import { ValidationError } from '@securityscan/shared';

export interface ParsedEndpoint {
  method: HttpMethod;
  path: string;
  operationId?: string;
  summary?: string;
  parameters: Array<{
    name: string;
    location: 'query' | 'path' | 'header' | 'body' | 'cookie';
    required: boolean;
    type: string;
    example?: string;
  }>;
  requestBody?: {
    contentType: string;
    schema?: Record<string, unknown>;
    required: boolean;
  };
  responses: Record<string, { description: string }>;
  security: string[];
  tags: string[];
}

export interface ParsedSchema {
  title: string;
  version: string;
  baseUrl: string;
  endpoints: ParsedEndpoint[];
  securitySchemes: Record<string, unknown>;
  valid: boolean;
  errors: string[];
}

export class OpenApiParser {
  parse(content: string, format: ApiSchemaFormat): ParsedSchema {
    let doc: Record<string, unknown>;
    try {
      if (format === ApiSchemaFormat.OPENAPI_YAML || format === ApiSchemaFormat.SWAGGER_YAML) {
        doc = YAML.parse(content) as Record<string, unknown>;
      } else {
        doc = JSON.parse(content) as Record<string, unknown>;
      }
    } catch (err) {
      throw new ValidationError(`Failed to parse specification: ${err instanceof Error ? err.message : 'unknown'}`);
    }

    const errors: string[] = [];
    const isSwagger = 'swagger' in doc;
    const isOpenApi = 'openapi' in doc;

    if (!isSwagger && !isOpenApi) {
      errors.push('Document is not a valid OpenAPI or Swagger specification');
      return { title: '', version: '', baseUrl: '', endpoints: [], securitySchemes: {}, valid: false, errors };
    }

    const info = (doc['info'] as Record<string, unknown>) ?? {};
    const title = (info['title'] as string) ?? '';
    const version = (info['version'] as string) ?? '';

    let baseUrl = '';
    if (isOpenApi) {
      const servers = doc['servers'] as Array<Record<string, unknown>> | undefined;
      baseUrl = (servers?.[0]?.['url'] as string) ?? '';
    } else {
      const host = (doc['host'] as string) ?? '';
      const basePath = (doc['basePath'] as string) ?? '';
      const schemes = (doc['schemes'] as string[]) ?? ['https'];
      baseUrl = `${schemes[0]}://${host}${basePath}`;
    }

    const paths = (doc['paths'] as Record<string, Record<string, unknown>>) ?? {};
    const endpoints: ParsedEndpoint[] = [];

    const components = (doc['components'] as Record<string, unknown>) ?? {};
    const securitySchemes = (components['securitySchemes'] as Record<string, unknown>) ?? {};

    for (const [path, methods] of Object.entries(paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        const httpMethod = method.toUpperCase() as HttpMethod;
        if (!Object.values(HttpMethod).includes(httpMethod)) continue;

        const op = operation as Record<string, unknown>;
        const params = (op['parameters'] as Array<Record<string, unknown>>) ?? [];
        const security = (op['security'] as Array<Record<string, unknown>>) ?? [];

        const parameters = params.map((p) => ({
          name: (p['name'] as string) ?? '',
          location: this.mapParamLocation(p['in'] as string),
          required: (p['required'] as boolean) ?? false,
          type: ((p['schema'] as Record<string, unknown>)?.['type'] as string) ?? 'string',
          example: (p['example'] as string) ?? undefined,
        }));

        let requestBody: ParsedEndpoint['requestBody'];
        const reqBody = op['requestBody'] as Record<string, unknown> | undefined;
        if (reqBody) {
          const content = (reqBody['content'] as Record<string, unknown>) ?? {};
          const firstContentType = Object.keys(content)[0] ?? 'application/json';
          requestBody = {
            contentType: firstContentType,
            schema: (content[firstContentType] as Record<string, unknown>)?.['schema'] as Record<string, unknown>,
            required: (reqBody['required'] as boolean) ?? false,
          };
        }

        const responses: Record<string, { description: string }> = {};
        const resps = (op['responses'] as Record<string, Record<string, unknown>>) ?? {};
        for (const [code, resp] of Object.entries(resps)) {
          responses[code] = { description: (resp['description'] as string) ?? '' };
        }

        endpoints.push({
          method: httpMethod,
          path,
          operationId: op['operationId'] as string | undefined,
          summary: op['summary'] as string | undefined,
          parameters,
          requestBody,
          responses,
          security: security.flatMap((s) => Object.keys(s)),
          tags: (op['tags'] as string[]) ?? [],
        });
      }
    }

    return {
      title,
      version,
      baseUrl,
      endpoints,
      securitySchemes,
      valid: errors.length === 0,
      errors,
    };
  }

  private mapParamLocation(input: string): 'query' | 'path' | 'header' | 'body' | 'cookie' {
    switch (input) {
      case 'query': return 'query';
      case 'path': return 'path';
      case 'header': return 'header';
      case 'cookie': return 'cookie';
      default: return 'body';
    }
  }
}
