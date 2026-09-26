import { describe, it, expect } from 'vitest';
import {
  AISecurityService,
  MockAIProvider,
  OpenAIProvider,
  AnthropicProvider,
  GeminiProvider,
  PreAiRedactionFilter,
  AIContextBuilder,
} from '../index.js';

describe('PreAiRedactionFilter', () => {
  it('redacts credit card numbers', () => {
    const raw = 'The customer card is 4111111111111111 in checkout';
    const redacted = PreAiRedactionFilter.redact(raw);
    expect(redacted).not.toContain('4111111111111111');
    expect(redacted).toContain('[REDACTED_BY_AI_GATE]');
  });

  it('redacts SSNs and emails', () => {
    const raw = 'User admin with email admin@corp.internal and SSN 000-12-3456';
    const redacted = PreAiRedactionFilter.redact(raw);
    expect(redacted).not.toContain('000-12-3456');
    expect(redacted).not.toContain('admin@corp.internal');
  });

  it('redacts JWT tokens', () => {
    const raw = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeak';
    const redacted = PreAiRedactionFilter.redact(raw);
    expect(redacted).not.toContain('doNotLeak');
  });
});

describe('AIContextBuilder', () => {
  it('constructs prompt with defensive system guardrails', () => {
    const messages = AIContextBuilder.buildFindingAnalysisPrompt({
      ruleId: 'SEC-HDR-001',
      ruleName: 'Missing HSTS',
      cwe: ['CWE-319'],
      owasp: ['A05:2021'],
      endpoint: 'https://example.com/api',
      method: 'GET',
      rawRequest: { method: 'GET', url: 'https://example.com/api', headers: {} },
      rawResponse: { statusCode: 200, headers: {}, body: 'OK' },
    });

    expect(messages).toHaveLength(2);
    expect(messages[0]?.content).toContain('GUARDRAILS');
    expect(messages[1]?.content).toContain('Rule ID: SEC-HDR-001');
  });
});

describe('AISecurityService', () => {
  it('processes and validates AI analysis with Zod schema', async () => {
    const provider = new MockAIProvider();
    const service = new AISecurityService(provider);

    const result = await service.analyzeFinding({
      ruleId: 'SEC-HDR-001',
      ruleName: 'Missing HSTS',
      cwe: ['CWE-319'],
      owasp: ['A05:2021'],
      endpoint: 'https://example.com/api',
      method: 'GET',
      rawRequest: { method: 'GET', url: 'https://example.com/api', headers: {} },
      rawResponse: { statusCode: 200, headers: {}, body: 'OK' },
    });

    expect(result).toBeDefined();
    expect(result?.falsePositiveLikelihood).toBe('LOW');
    expect(result?.tailoredRemediation).toBeDefined();
  });

  it('gracefully handles invalid schema output', async () => {
    const provider = new MockAIProvider(JSON.stringify({ unexpected: 'format' }));
    const service = new AISecurityService(provider);

    const result = await service.analyzeFinding({
      ruleId: 'SEC-HDR-001',
      ruleName: 'Missing HSTS',
      cwe: ['CWE-319'],
      owasp: ['A05:2021'],
      endpoint: 'https://example.com/api',
      method: 'GET',
      rawRequest: { method: 'GET', url: 'https://example.com/api', headers: {} },
      rawResponse: { statusCode: 200, headers: {}, body: 'OK' },
    });

    expect(result).toBeNull();
  });
});

describe('AI Providers Zod Validation', () => {
  it('validates OpenAI provider completions', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            choices: [{ message: { content: 'test response from openai' } }],
          }),
          { status: 200 },
        );

      const provider = new OpenAIProvider('test-key');
      const response = await provider.generateCompletion([{ role: 'user', content: 'hello' }]);
      expect(response).toBe('test response from openai');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('validates Anthropic provider completions', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            content: [{ type: 'text', text: 'test response from claude' }],
          }),
          { status: 200 },
        );

      const provider = new AnthropicProvider('test-key');
      const response = await provider.generateCompletion([{ role: 'user', content: 'hello' }]);
      expect(response).toBe('test response from claude');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('validates Gemini provider completions', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: 'test response from gemini' }] } }],
          }),
          { status: 200 },
        );

      const provider = new GeminiProvider('test-key');
      const response = await provider.generateCompletion([{ role: 'user', content: 'hello' }]);
      expect(response).toBe('test response from gemini');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
