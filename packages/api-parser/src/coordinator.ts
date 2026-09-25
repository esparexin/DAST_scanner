import { ApiSchemaFormat, ApiType, HttpMethod } from '@securityscan/contracts';
import { OpenApiParser } from '@securityscan/openapi';
import { GraphQLIntrospection } from '@securityscan/graphql';
import type { UnifiedApiDefinition, NormalizedApiEndpoint } from './types.js';
import { ValidationError } from '@securityscan/shared';

export class ApiParserCoordinator {
  private readonly openApiParser = new OpenApiParser();
  private readonly graphqlParser = new GraphQLIntrospection();

  parse(content: string, format: ApiSchemaFormat): UnifiedApiDefinition {
    switch (format) {
      case ApiSchemaFormat.OPENAPI_JSON:
      case ApiSchemaFormat.OPENAPI_YAML:
      case ApiSchemaFormat.SWAGGER_JSON:
      case ApiSchemaFormat.SWAGGER_YAML:
        return this.parseOpenApi(content, format);

      case ApiSchemaFormat.GRAPHQL_INTROSPECTION:
      case ApiSchemaFormat.GRAPHQL_SDL:
        return this.parseGraphQL(content, format);

      case ApiSchemaFormat.WSDL:
        return this.parseWsdl(content);

      default:
        throw new ValidationError(`Unsupported schema format: ${format}`);
    }
  }

  private parseOpenApi(content: string, format: ApiSchemaFormat): UnifiedApiDefinition {
    const parsed = this.openApiParser.parse(content, format);
    const endpoints: NormalizedApiEndpoint[] = parsed.endpoints.map((e) => {
      const declaredProps: Record<string, string[]> = {};
      // Extract properties declared in responses
      for (const [code] of Object.entries(e.responses)) {
        declaredProps[code] = [];
      }

      return {
        path: e.path,
        method: e.method,
        operationId: e.operationId,
        summary: e.summary,
        parameters: e.parameters.map((p) => ({
          name: p.name,
          location: p.location,
          required: p.required,
          type: p.type,
        })),
        declaredResponseProperties: declaredProps,
        security: e.security,
      };
    });

    return {
      title: parsed.title,
      version: parsed.version,
      type: ApiType.REST,
      format,
      baseUrl: parsed.baseUrl,
      endpoints,
      rawSchema: content,
      valid: parsed.valid,
      errors: parsed.errors,
    };
  }

  private parseGraphQL(content: string, format: ApiSchemaFormat): UnifiedApiDefinition {
    let parsedJson: Record<string, unknown>;
    try {
      parsedJson = JSON.parse(content);
    } catch {
      return {
        title: 'GraphQL API',
        version: '1.0',
        type: ApiType.GRAPHQL,
        format,
        baseUrl: '',
        endpoints: [],
        rawSchema: content,
        valid: false,
        errors: ['Invalid JSON for GraphQL introspection'],
      };
    }

    const introspection = this.graphqlParser.parseIntrospection(parsedJson);
    const endpoints: NormalizedApiEndpoint[] = [];

    // Map queries and mutations to normalized endpoints
    for (const type of introspection.types) {
      if (type.name === introspection.queryType || type.name === introspection.mutationType) {
        for (const field of type.fields ?? []) {
          endpoints.push({
            path: `/graphql#${field.name}`,
            method: HttpMethod.POST,
            operationId: field.name,
            summary: `${type.name} field: ${field.name}`,
            parameters: field.args.map((a) => ({
              name: a.name,
              location: 'body' as const,
              required: a.type.endsWith('!'),
              type: a.type,
            })),
            security: [],
          });
        }
      }
    }

    return {
      title: 'GraphQL Service',
      version: '1.0',
      type: ApiType.GRAPHQL,
      format,
      baseUrl: '',
      endpoints,
      rawSchema: content,
      valid: introspection.introspectionEnabled,
      errors: [],
    };
  }

  private parseWsdl(content: string): UnifiedApiDefinition {
    const opRegex = /<wsdl:operation[^>]*name=["']([^"']+)["']/gi;
    const operations: string[] = [];
    let match;
    while ((match = opRegex.exec(content)) !== null) {
      if (match[1] && !operations.includes(match[1])) {
        operations.push(match[1]);
      }
    }

    const endpoints: NormalizedApiEndpoint[] = operations.map((op) => ({
      path: `/${op}`,
      method: HttpMethod.POST,
      operationId: op,
      summary: `SOAP Operation: ${op}`,
      parameters: [],
      security: [],
    }));

    return {
      title: 'SOAP Web Service',
      version: '1.1',
      type: ApiType.SOAP,
      format: ApiSchemaFormat.WSDL,
      baseUrl: '',
      endpoints,
      rawSchema: content,
      valid: operations.length > 0,
      errors: operations.length === 0 ? ['No operations discovered in WSDL'] : [],
    };
  }
}
