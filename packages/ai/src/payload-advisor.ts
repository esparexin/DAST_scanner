import type { AIProvider } from './types.js';
import type { IPayloadDefinition } from '@securityscan/payload-engine';
import { PreAiRedactionFilter } from './redaction-filter.js';
import { z } from 'zod';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('ai-payload-advisor');

export interface PayloadRecommendationRequest {
  endpointUrl: string;
  method: string;
  parameterName: string;
  parameterLocation: string;
  parameterType: string;
  reflectionContext?: string;
  schemaConstraints?: {
    type?: string;
    format?: string;
    enum?: string[];
    minLength?: number;
    maxLength?: number;
  };
  observedBehavior?: string;
}

export interface PayloadRecommendation {
  recommendedCategories: string[];
  recommendedSubcategories: string[];
  reasoning: string;
  priorityOrder: string[];
  skipReasons: Record<string, string>;
  provider: string;
  modelUsed: string;
}

const RecommendationResponseSchema = z.object({
  recommendedCategories: z.array(z.string()),
  recommendedSubcategories: z.array(z.string()),
  reasoning: z.string(),
  priorityOrder: z.array(z.string()),
  skipReasons: z.record(z.string()).default({}),
});

/**
 * AI-Assisted Payload Recommendation Service.
 *
 * SAFETY BOUNDARY:
 * - AI RECOMMENDS payload families/categories only
 * - AI CANNOT generate payloads, execute requests, bypass scope, or confirm findings
 * - All recommendations are validated against PayloadRegistry eligibility before use
 * - Endpoint URLs and credentials are redacted before sending to AI
 */
export class AIPayloadAdvisor {
  private readonly provider: AIProvider;
  private readonly redactionFilter: PreAiRedactionFilter;

  constructor(provider: AIProvider) {
    this.provider = provider;
    this.redactionFilter = new PreAiRedactionFilter();
  }

  async recommend(
    request: PayloadRecommendationRequest,
  ): Promise<PayloadRecommendation> {
    const prompt = this.buildPrompt(request);
    const rawResponse = this.provider.complete
      ? await this.provider.complete(prompt)
      : await this.provider.generateCompletion([{ role: 'user', content: prompt }]);

    try {
      const parsed = JSON.parse(rawResponse);
      const validated = RecommendationResponseSchema.parse(parsed);

      return {
        ...validated,
        provider: this.provider.name,
        modelUsed: this.provider.model ?? this.provider.name,
      };
    } catch {
      logger.warn('AI recommendation response could not be parsed, returning empty recommendation');
      return {
        recommendedCategories: [],
        recommendedSubcategories: [],
        reasoning: 'AI response could not be parsed. Falling back to deterministic selection.',
        priorityOrder: [],
        skipReasons: {},
        provider: this.provider.name,
        modelUsed: this.provider.model ?? this.provider.name,
      };
    }
  }

  /**
   * Validate AI recommendations against actual registry contents.
   * Only categories that exist in the registry with ACTIVE payloads pass through.
   */
  filterByRegistryEligibility(
    recommendation: PayloadRecommendation,
    availablePayloads: IPayloadDefinition[],
  ): string[] {
    const activeCategories = new Set(
      availablePayloads
        .filter((p) => p.status === 'ACTIVE')
        .map((p) => p.category),
    );

    return recommendation.recommendedCategories.filter((cat) =>
      activeCategories.has(cat as any),
    );
  }

  private buildPrompt(request: PayloadRecommendationRequest): string {
    // Redact sensitive URL components
    const safeUrl = this.redactionFilter.redactUrl(request.endpointUrl);

    return [
      'You are a security testing advisor. Based on the following endpoint parameter context,',
      'recommend which CATEGORIES of security test payloads should be prioritized.',
      '',
      'IMPORTANT: You may ONLY recommend categories. You CANNOT generate payloads, execute requests, or bypass scope controls.',
      '',
      '<DATA>',
      `Endpoint: ${safeUrl}`,
      `Method: ${request.method}`,
      `Parameter: ${request.parameterName}`,
      `Location: ${request.parameterLocation}`,
      `Type: ${request.parameterType}`,
      request.reflectionContext ? `Reflection Context: ${request.reflectionContext}` : '',
      request.schemaConstraints ? `Schema: ${JSON.stringify(request.schemaConstraints)}` : '',
      request.observedBehavior ? `Observed Behavior: ${request.observedBehavior}` : '',
      '</DATA>',
      '',
      'Available categories: INJECTION, XSS, PATH_TRAVERSAL, SSRF, AUTHENTICATION, AUTHORIZATION,',
      'MISCONFIGURATION, CRYPTOGRAPHY, CSRF, FILE_UPLOAD',
      '',
      'Respond with a JSON object containing:',
      '- recommendedCategories: string[] of category names',
      '- recommendedSubcategories: string[] of specific subcategory names',
      '- reasoning: string explaining your analysis',
      '- priorityOrder: string[] categories in priority order',
      '- skipReasons: Record<string, string> for categories you recommend skipping and why',
    ]
      .filter(Boolean)
      .join('\n');
  }
}
