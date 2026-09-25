import { z } from 'zod';

export interface AIModelMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface AICompletionOptions {
  temperature?: number;
  maxTokens?: number;
  jsonMode?: boolean;
}

export interface IAIProvider {
  readonly name: string;
  generateCompletion(messages: AIModelMessage[], options?: AICompletionOptions): Promise<string>;
}

// Structured schemas for validated AI outputs
export const AiFindingAnalysisSchema = z.object({
  rootCauseSummary: z.string().min(1),
  technicalImpact: z.string().min(1),
  falsePositiveLikelihood: z.enum(['VERY_LOW', 'LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH']),
  falsePositiveRationale: z.string(),
  suggestedVerificationStrategy: z.string(),
  tailoredRemediation: z.string().min(1),
  remediationCodeSample: z.string().optional(),
});

export type AiFindingAnalysis = z.infer<typeof AiFindingAnalysisSchema>;

export const AiSchemaAnalysisSchema = z.object({
  sensitiveParametersIdentified: z.array(
    z.object({
      parameterName: z.string(),
      location: z.string(),
      sensitivityCategory: z.enum(['CREDENTIAL', 'PII', 'FINANCIAL', 'INTERNAL_IDENTIFIER', 'PRIVILEGE']),
      rationale: z.string(),
    }),
  ),
  highRiskEndpoints: z.array(
    z.object({
      path: z.string(),
      method: z.string(),
      attackVectors: z.array(z.string()),
    }),
  ),
  recommendedCustomTestCases: z.array(z.string()),
});

export type AiSchemaAnalysis = z.infer<typeof AiSchemaAnalysisSchema>;
