import { describe, it, expect } from 'vitest';
import { GraphQLIntrospection } from '../introspection.js';

describe('GraphQLIntrospection', () => {
  const intro = new GraphQLIntrospection();

  it('builds an introspection query', () => {
    const query = intro.buildIntrospectionQuery();
    expect(query).toContain('__schema');
    expect(query).toContain('queryType');
    expect(query).toContain('types');
  });

  it('parses introspection response', () => {
    const response = {
      data: {
        __schema: {
          queryType: { name: 'Query' },
          mutationType: { name: 'Mutation' },
          types: [
            { name: 'Query', kind: 'OBJECT', fields: [{ name: 'users', type: { name: 'User', kind: 'OBJECT' }, args: [] }] },
            { name: 'User', kind: 'OBJECT', fields: [{ name: 'id', type: { name: 'ID', kind: 'SCALAR' }, args: [] }, { name: 'name', type: { name: 'String', kind: 'SCALAR' }, args: [] }] },
            { name: '__Schema', kind: 'OBJECT', fields: [] },
          ],
        },
      },
    };
    const result = intro.parseIntrospection(response);
    expect(result.queryType).toBe('Query');
    expect(result.mutationType).toBe('Mutation');
    expect(result.introspectionEnabled).toBe(true);
    expect(result.types).toHaveLength(2); // __Schema filtered out
    expect(result.types.find((t) => t.name === 'User')?.fields).toHaveLength(2);
  });

  it('handles empty introspection', () => {
    const result = intro.parseIntrospection({ data: { __schema: {} } });
    expect(result.introspectionEnabled).toBe(false);
    expect(result.types).toHaveLength(0);
  });
});
