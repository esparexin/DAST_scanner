import { describe, it, expect, vi } from 'vitest';
import { AIPayloadAdvisor } from '../payload-advisor.js';
import type { AIProvider } from '../types.js';
import type { IPayloadDefinition } from '@securityscan/payload-engine';
import { DetectionCategory } from '@securityscan/contracts';

const mockPayloads: IPayloadDefinition[] = [
  {
    id: 'PL-SQLI-001',
    name: 'SQLi Probe',
    version: '1.0.0',
    status: 'ACTIVE',
    category: DetectionCategory.INJECTION,
    subcategory: 'error-based',
    description: 'Test',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: { raw: "'", supportedTransformations: ['NONE'] },
    applicability: {
      parameterLocations: ['query'],
      parameterTypes: ['string'],
      targetContexts: ['ANY'],
      protocols: ['HTTP'],
    },
    detection: { strategy: 'ERROR_SIGNATURE', errorSignatures: ['sql'] },
    verification: { strategy: 'REPLAY_PROBE_CONFIRMATION', replayAttemptsRequired: 2 },
    references: { cwe: ['CWE-89'], owaspTop10: ['A03:2021'], owaspApiSecurity: [] },
    remediation: { concept: 'Use parameterized queries', guidance: 'Fix it' },
  },
  {
    id: 'PL-XSS-001',
    name: 'XSS Probe',
    version: '1.0.0',
    status: 'DEPRECATED',
    category: DetectionCategory.XSS,
    subcategory: 'reflected',
    description: 'Deprecated XSS probe',
    safetyLevel: 'BOUNDED_ACTIVE',
    template: { raw: '<x>', supportedTransformations: ['NONE'] },
    applicability: {
      parameterLocations: ['query'],
      parameterTypes: ['string'],
      targetContexts: ['ANY'],
      protocols: ['HTTP'],
    },
    detection: { strategy: 'CANARY_REFLECTION' },
    verification: { strategy: 'TOKEN_EQUIVALENCE', replayAttemptsRequired: 1 },
    references: { cwe: ['CWE-79'], owaspTop10: ['A03:2021'], owaspApiSecurity: [] },
    remediation: { concept: 'Encode output', guidance: 'Fix it' },
  },
];

describe('AIPayloadAdvisor', () => {
  it('parses valid AI JSON recommendation', async () => {
    const mockProvider: AIProvider = {
      name: 'mock',
      model: 'mock-v1',
      complete: vi.fn().mockResolvedValue(
        JSON.stringify({
          recommendedCategories: ['INJECTION', 'XSS'],
          recommendedSubcategories: ['error-based', 'reflected'],
          reasoning: 'String parameter in query position is injection-susceptible',
          priorityOrder: ['INJECTION', 'XSS'],
          skipReasons: { CSRF: 'GET method, not applicable' },
        }),
      ),
    };

    const advisor = new AIPayloadAdvisor(mockProvider);
    const result = await advisor.recommend({
      endpointUrl: 'https://api.example.com/users?search=test',
      method: 'GET',
      parameterName: 'search',
      parameterLocation: 'query',
      parameterType: 'string',
    });

    expect(result.recommendedCategories).toEqual(['INJECTION', 'XSS']);
    expect(result.reasoning).toContain('injection-susceptible');
    expect(result.skipReasons.CSRF).toBeDefined();
    expect(result.provider).toBe('mock');
  });

  it('returns empty recommendation on unparseable AI response', async () => {
    const mockProvider: AIProvider = {
      name: 'mock',
      model: 'mock-v1',
      complete: vi.fn().mockResolvedValue('I am not sure, perhaps try SQL injection?'),
    };

    const advisor = new AIPayloadAdvisor(mockProvider);
    const result = await advisor.recommend({
      endpointUrl: 'https://api.example.com/users',
      method: 'POST',
      parameterName: 'email',
      parameterLocation: 'body',
      parameterType: 'string',
    });

    expect(result.recommendedCategories).toEqual([]);
    expect(result.reasoning).toContain('Falling back');
  });

  it('filters recommendations against registry eligibility (only ACTIVE payloads)', () => {
    const mockProvider: AIProvider = {
      name: 'mock',
      model: 'mock-v1',
      complete: vi.fn(),
    };

    const advisor = new AIPayloadAdvisor(mockProvider);
    const recommendation = {
      recommendedCategories: ['INJECTION', 'XSS', 'PATH_TRAVERSAL'],
      recommendedSubcategories: [],
      reasoning: 'Test',
      priorityOrder: [],
      skipReasons: {},
      provider: 'mock',
      modelUsed: 'mock-v1',
    };

    // XSS payload is DEPRECATED, so should be filtered out
    const eligible = advisor.filterByRegistryEligibility(recommendation, mockPayloads);
    expect(eligible).toContain('INJECTION');
    expect(eligible).not.toContain('XSS');
    expect(eligible).not.toContain('PATH_TRAVERSAL');
  });

  it('redacts sensitive URL components in AI prompt', async () => {
    let capturedPrompt = '';
    const mockProvider: AIProvider = {
      name: 'mock',
      model: 'mock-v1',
      complete: vi.fn().mockImplementation((prompt: string) => {
        capturedPrompt = prompt;
        return Promise.resolve(JSON.stringify({
          recommendedCategories: [],
          recommendedSubcategories: [],
          reasoning: 'No recommendations',
          priorityOrder: [],
          skipReasons: {},
        }));
      }),
    };

    const advisor = new AIPayloadAdvisor(mockProvider);
    await advisor.recommend({
      endpointUrl: 'https://api.example.com/v1/data?api_key=SUPERSECRETKEY123456&q=test',
      method: 'GET',
      parameterName: 'q',
      parameterLocation: 'query',
      parameterType: 'string',
    });

    expect(capturedPrompt).not.toContain('SUPERSECRETKEY123456');
    expect(capturedPrompt).toContain('[REDACTED]');
  });
});
