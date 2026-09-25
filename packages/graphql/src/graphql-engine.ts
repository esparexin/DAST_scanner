import type { SecureHttpClient } from '@securityscan/http-client';
import { HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';
import { GraphQLIntrospection, type GqlType } from './introspection.js';

const logger = createLogger('graphql-engine');

export interface GraphQLEndpoint {
  url: string;
  introspectionEnabled: boolean;
  queryType: string | null;
  mutationType: string | null;
  types: GqlType[];
}

export class GraphQLEngine {
  private readonly httpClient: SecureHttpClient;
  private readonly introspection = new GraphQLIntrospection();

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Discover and introspect a GraphQL endpoint.
   */
  async discover(url: string): Promise<GraphQLEndpoint> {
    const query = this.introspection.buildIntrospectionQuery();
    try {
      const response = await this.httpClient.request({
        method: HttpMethod.POST,
        url,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });

      const parsed = JSON.parse(response.body) as Record<string, unknown>;
      const schema = this.introspection.parseIntrospection(parsed);

      logger.info({ url, types: schema.types.length, introspection: schema.introspectionEnabled }, 'GraphQL endpoint discovered');

      return {
        url,
        introspectionEnabled: schema.introspectionEnabled,
        queryType: schema.queryType,
        mutationType: schema.mutationType,
        types: schema.types,
      };
    } catch (error) {
      logger.debug({ url, error: (error as Error).message }, 'GraphQL introspection failed');
      return {
        url,
        introspectionEnabled: false,
        queryType: null,
        mutationType: null,
        types: [],
      };
    }
  }

  /**
   * Send a GraphQL query.
   */
  async query(url: string, queryStr: string, variables?: Record<string, unknown>, headers?: Record<string, string>) {
    const response = await this.httpClient.request({
      method: HttpMethod.POST,
      url,
      headers: { 'Content-Type': 'application/json', ...(headers ?? {}) },
      body: JSON.stringify({ query: queryStr, variables }),
    });
    return {
      statusCode: response.statusCode,
      data: JSON.parse(response.body) as Record<string, unknown>,
      headers: response.headers,
      responseTime: response.responseTime,
    };
  }

  /**
   * Check for common GraphQL security issues.
   */
  analyzeSchema(endpoint: GraphQLEndpoint): string[] {
    const issues: string[] = [];

    if (endpoint.introspectionEnabled) {
      issues.push('GraphQL introspection is enabled (should be disabled in production)');
    }

    // Check for potentially sensitive types
    for (const type of endpoint.types) {
      if (type.fields) {
        for (const field of type.fields) {
          const lower = field.name.toLowerCase();
          if (['password', 'secret', 'token', 'apikey', 'ssn', 'creditcard'].some((s) => lower.includes(s))) {
            issues.push(`Potentially sensitive field exposed: ${type.name}.${field.name}`);
          }
        }
      }
    }

    return issues;
  }
}
