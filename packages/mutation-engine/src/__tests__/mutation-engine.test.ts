import { describe, it, expect } from 'vitest';
import { MutationEngine } from '../mutation-engine.js';

describe('MutationEngine', () => {
  const engine = new MutationEngine();

  describe('mutateJsonBody', () => {
    it('generates missing parameter mutations', () => {
      const results = engine.mutateJsonBody({ name: 'test', age: 25 });
      const missingName = results.find((r) => r.mutation.type === 'missing_param' && r.mutation.field === 'name');
      expect(missingName).toBeDefined();
      expect(missingName!.body).not.toHaveProperty('name');
    });

    it('generates null value mutations', () => {
      const results = engine.mutateJsonBody({ name: 'test' });
      const nullMut = results.find((r) => r.mutation.type === 'null_value' && r.mutation.field === 'name');
      expect(nullMut).toBeDefined();
      expect(nullMut!.body['name']).toBeNull();
    });

    it('generates type change mutations for strings', () => {
      const results = engine.mutateJsonBody({ name: 'test' });
      const typeMut = results.filter((r) => r.mutation.type === 'type_change');
      expect(typeMut.length).toBeGreaterThanOrEqual(2);
    });

    it('generates boundary mutations for numbers', () => {
      const results = engine.mutateJsonBody({ count: 5 });
      const boundary = results.filter((r) => r.mutation.type === 'boundary');
      expect(boundary.length).toBeGreaterThanOrEqual(3);
    });

    it('generates extra parameter mutation', () => {
      const results = engine.mutateJsonBody({ name: 'test' });
      const extra = results.find((r) => r.mutation.type === 'extra_param');
      expect(extra).toBeDefined();
      expect(extra!.body).toHaveProperty('__admin');
    });
  });

  describe('mutatePath', () => {
    it('replaces numeric IDs', () => {
      const results = engine.mutatePath('/api/users/42/posts/7');
      expect(results.length).toBeGreaterThan(0);
      expect(results.some((r) => r.path.includes('/0/'))).toBe(true);
    });

    it('handles paths without IDs', () => {
      const results = engine.mutatePath('/api/health');
      expect(results).toHaveLength(0);
    });
  });

  describe('mutateMethods', () => {
    it('returns all methods except original', () => {
      const methods = engine.mutateMethods('GET');
      expect(methods).not.toContain('GET');
      expect(methods).toContain('POST');
      expect(methods).toContain('DELETE');
    });
  });
});
