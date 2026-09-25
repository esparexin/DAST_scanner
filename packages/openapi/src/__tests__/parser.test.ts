import { describe, it, expect } from 'vitest';
import { OpenApiParser } from '../parser.js';
import { ApiSchemaFormat } from '@securityscan/contracts';

const SAMPLE_OPENAPI = JSON.stringify({
  openapi: '3.0.0',
  info: { title: 'Pet Store', version: '1.0.0' },
  servers: [{ url: 'https://api.example.com/v1' }],
  paths: {
    '/pets': {
      get: {
        operationId: 'listPets',
        summary: 'List all pets',
        parameters: [
          { name: 'limit', in: 'query', schema: { type: 'integer' }, required: false },
        ],
        responses: { '200': { description: 'A list of pets' } },
        tags: ['pets'],
      },
      post: {
        operationId: 'createPet',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object' } } },
        },
        responses: { '201': { description: 'Created' } },
        tags: ['pets'],
      },
    },
    '/pets/{petId}': {
      get: {
        operationId: 'getPet',
        parameters: [
          { name: 'petId', in: 'path', schema: { type: 'string' }, required: true },
        ],
        responses: { '200': { description: 'A pet' } },
        security: [{ bearerAuth: [] }],
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer' },
    },
  },
});

describe('OpenApiParser', () => {
  const parser = new OpenApiParser();

  it('parses OpenAPI JSON correctly', () => {
    const result = parser.parse(SAMPLE_OPENAPI, ApiSchemaFormat.OPENAPI_JSON);
    expect(result.valid).toBe(true);
    expect(result.title).toBe('Pet Store');
    expect(result.version).toBe('1.0.0');
    expect(result.baseUrl).toBe('https://api.example.com/v1');
    expect(result.endpoints).toHaveLength(3);
  });

  it('extracts GET /pets endpoint', () => {
    const result = parser.parse(SAMPLE_OPENAPI, ApiSchemaFormat.OPENAPI_JSON);
    const listPets = result.endpoints.find((e) => e.operationId === 'listPets');
    expect(listPets).toBeDefined();
    expect(listPets!.method).toBe('GET');
    expect(listPets!.path).toBe('/pets');
    expect(listPets!.parameters).toHaveLength(1);
    expect(listPets!.parameters[0]!.name).toBe('limit');
  });

  it('extracts POST /pets with request body', () => {
    const result = parser.parse(SAMPLE_OPENAPI, ApiSchemaFormat.OPENAPI_JSON);
    const createPet = result.endpoints.find((e) => e.operationId === 'createPet');
    expect(createPet).toBeDefined();
    expect(createPet!.method).toBe('POST');
    expect(createPet!.requestBody).toBeDefined();
    expect(createPet!.requestBody!.contentType).toBe('application/json');
  });

  it('extracts security requirements', () => {
    const result = parser.parse(SAMPLE_OPENAPI, ApiSchemaFormat.OPENAPI_JSON);
    const getPet = result.endpoints.find((e) => e.operationId === 'getPet');
    expect(getPet!.security).toContain('bearerAuth');
  });

  it('extracts security schemes', () => {
    const result = parser.parse(SAMPLE_OPENAPI, ApiSchemaFormat.OPENAPI_JSON);
    expect(result.securitySchemes).toHaveProperty('bearerAuth');
  });

  it('rejects invalid documents', () => {
    const result = parser.parse('{}', ApiSchemaFormat.OPENAPI_JSON);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('throws on invalid JSON', () => {
    expect(() => parser.parse('not json', ApiSchemaFormat.OPENAPI_JSON)).toThrow();
  });
});
