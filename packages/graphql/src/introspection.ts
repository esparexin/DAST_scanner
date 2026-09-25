export interface GqlType {
  name: string;
  kind: string;
  fields?: GqlField[];
}

export interface GqlField {
  name: string;
  type: string;
  args: Array<{ name: string; type: string }>;
}

/**
 * Parse a GraphQL introspection response into a usable schema.
 */
export class GraphQLIntrospection {
  parseIntrospection(response: Record<string, unknown>): {
    queryType: string | null;
    mutationType: string | null;
    types: GqlType[];
    introspectionEnabled: boolean;
  } {
    const data = (response['data'] as Record<string, unknown>) ?? response;
    const schema = (data['__schema'] as Record<string, unknown>) ?? {};

    const queryType = (schema['queryType'] as Record<string, string>)?.['name'] ?? null;
    const mutationType = (schema['mutationType'] as Record<string, string>)?.['name'] ?? null;
    const rawTypes = (schema['types'] as Array<Record<string, unknown>>) ?? [];

    const types: GqlType[] = rawTypes
      .filter((t) => {
        const name = t['name'] as string;
        return name && !name.startsWith('__');
      })
      .map((t) => ({
        name: (t['name'] as string) ?? '',
        kind: (t['kind'] as string) ?? '',
        fields: ((t['fields'] as Array<Record<string, unknown>>) ?? []).map((f) => ({
          name: (f['name'] as string) ?? '',
          type: this.extractTypeName(f['type'] as Record<string, unknown>),
          args: ((f['args'] as Array<Record<string, unknown>>) ?? []).map((a) => ({
            name: (a['name'] as string) ?? '',
            type: this.extractTypeName(a['type'] as Record<string, unknown>),
          })),
        })),
      }));

    return { queryType, mutationType, types, introspectionEnabled: types.length > 0 };
  }

  private extractTypeName(type: Record<string, unknown> | undefined): string {
    if (!type) return 'unknown';
    const kind = type['kind'] as string;
    const name = type['name'] as string | null;
    if (name) return name;
    if (kind === 'NON_NULL' || kind === 'LIST') {
      const ofType = type['ofType'] as Record<string, unknown>;
      return `${kind === 'NON_NULL' ? '' : '['}${this.extractTypeName(ofType)}${kind === 'LIST' ? ']' : '!'}`;
    }
    return 'unknown';
  }

  buildIntrospectionQuery(): string {
    return `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind ofType { name kind } } }
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}`;
  }
}
