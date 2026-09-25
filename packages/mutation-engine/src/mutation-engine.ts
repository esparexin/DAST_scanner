export type MutationType =
  | 'missing_param'
  | 'extra_param'
  | 'type_change'
  | 'boundary'
  | 'null_value'
  | 'empty_value'
  | 'invalid_enum'
  | 'path_id_change'
  | 'method_change'
  | 'content_type_change'
  | 'auth_change';

export interface Mutation {
  type: MutationType;
  description: string;
  field?: string;
  originalValue?: unknown;
  mutatedValue?: unknown;
}

/**
 * Generates controlled mutations of API requests for security testing.
 * All mutations are deterministic and pass through scope validation.
 */
export class MutationEngine {
  /**
   * Generate mutations for a JSON body based on its schema.
   */
  mutateJsonBody(body: Record<string, unknown>, _schema?: Record<string, unknown>): Array<{ mutation: Mutation; body: Record<string, unknown> }> {
    const results: Array<{ mutation: Mutation; body: Record<string, unknown> }> = [];

    for (const [key, value] of Object.entries(body)) {
      // Missing parameter
      const withoutKey = { ...body };
      delete withoutKey[key];
      results.push({
        mutation: { type: 'missing_param', description: `Remove parameter '${key}'`, field: key, originalValue: value },
        body: withoutKey,
      });

      // Null value
      results.push({
        mutation: { type: 'null_value', description: `Set '${key}' to null`, field: key, originalValue: value, mutatedValue: null },
        body: { ...body, [key]: null },
      });

      // Empty value
      results.push({
        mutation: { type: 'empty_value', description: `Set '${key}' to empty`, field: key, originalValue: value, mutatedValue: '' },
        body: { ...body, [key]: '' },
      });

      // Type changes
      if (typeof value === 'string') {
        results.push({
          mutation: { type: 'type_change', description: `Change '${key}' from string to number`, field: key, originalValue: value, mutatedValue: 12345 },
          body: { ...body, [key]: 12345 },
        });
        results.push({
          mutation: { type: 'type_change', description: `Change '${key}' from string to boolean`, field: key, originalValue: value, mutatedValue: true },
          body: { ...body, [key]: true },
        });
      }
      if (typeof value === 'number') {
        results.push({
          mutation: { type: 'boundary', description: `Set '${key}' to MAX_SAFE_INTEGER`, field: key, originalValue: value, mutatedValue: Number.MAX_SAFE_INTEGER },
          body: { ...body, [key]: Number.MAX_SAFE_INTEGER },
        });
        results.push({
          mutation: { type: 'boundary', description: `Set '${key}' to negative`, field: key, originalValue: value, mutatedValue: -1 },
          body: { ...body, [key]: -1 },
        });
        results.push({
          mutation: { type: 'boundary', description: `Set '${key}' to zero`, field: key, originalValue: value, mutatedValue: 0 },
          body: { ...body, [key]: 0 },
        });
      }
    }

    // Extra parameter
    results.push({
      mutation: { type: 'extra_param', description: 'Add unexpected parameter', field: '__admin', mutatedValue: true },
      body: { ...body, __admin: true, isAdmin: true, role: 'admin' },
    });

    return results;
  }

  /**
   * Generate path mutations for BOLA/IDOR testing.
   */
  mutatePath(path: string): Array<{ mutation: Mutation; path: string }> {
    const results: Array<{ mutation: Mutation; path: string }> = [];
    // Replace numeric IDs
    const idPattern = /\/([0-9]+)/g;
    if (idPattern.test(path)) {
      for (const replacement of ['0', '1', '99999', '-1']) {
        const mutated = path.replace(/\/([0-9]+)/g, `/${replacement}`);
        if (mutated !== path) {
          results.push({
            mutation: { type: 'path_id_change', description: `Replace ID with ${replacement}`, mutatedValue: replacement },
            path: mutated,
          });
        }
      }
    }

    // Replace UUID-like IDs
    const uuidPattern = /\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi;
    if (uuidPattern.test(path)) {
      const mutated = path.replace(uuidPattern, '/00000000-0000-0000-0000-000000000000');
      results.push({
        mutation: { type: 'path_id_change', description: 'Replace UUID with zeroes', mutatedValue: '00000000-0000-0000-0000-000000000000' },
        path: mutated,
      });
    }

    return results;
  }

  /**
   * Generate HTTP method mutations.
   */
  mutateMethods(originalMethod: string): string[] {
    const allMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
    return allMethods.filter((m) => m !== originalMethod.toUpperCase());
  }
}
