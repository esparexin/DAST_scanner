import type { IAIProvider, AiFindingAnalysis } from './types.js';
import { AiFindingAnalysisSchema } from './types.js';
import { AIContextBuilder, type FindingEvidenceContext } from './context-builder.js';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('ai-service');

export class AISecurityService {
  private readonly provider: IAIProvider;

  constructor(provider: IAIProvider) {
    this.provider = provider;
  }

  /**
   * Analyze a finding with validated structured output.
   * Validates response through Zod schema to ensure no hallucinated format.
   */
  async analyzeFinding(evidence: FindingEvidenceContext): Promise<AiFindingAnalysis | null> {
    try {
      const messages = AIContextBuilder.buildFindingAnalysisPrompt(evidence);
      const rawResponse = await this.provider.generateCompletion(messages, {
        temperature: 0.1,
        jsonMode: true,
      });

      const cleanedJson = this.extractJson(rawResponse);
      const parsed = JSON.parse(cleanedJson);
      const validated = AiFindingAnalysisSchema.parse(parsed);

      logger.debug({ ruleId: evidence.ruleId, provider: this.provider.name }, 'Finding analyzed by AI successfully');
      return validated;
    } catch (error) {
      logger.warn(
        { ruleId: evidence.ruleId, error: (error as Error).message },
        'AI finding analysis failed or output failed validation',
      );
      return null;
    }
  }

  private extractJson(text: string): string {
    const trimmed = text.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) return trimmed;
    const match = /```(?:json)?\s*([\s\S]*?)\s*```/.exec(trimmed);
    if (match?.[1]) return match[1].trim();
    return trimmed;
  }
}
