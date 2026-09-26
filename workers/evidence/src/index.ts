import { FindingModel } from '@securityscan/database';
import { FindingStatus } from '@securityscan/contracts';
import { AISecurityService, MockAIProvider, OpenAIProvider, GeminiProvider, AnthropicProvider } from '@securityscan/ai';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('worker-evidence');

function getAiService(): AISecurityService {
  if (process.env['OPENAI_API_KEY']) return new AISecurityService(new OpenAIProvider());
  if (process.env['GEMINI_API_KEY']) return new AISecurityService(new GeminiProvider());
  if (process.env['ANTHROPIC_API_KEY']) return new AISecurityService(new AnthropicProvider());
  return new AISecurityService(new MockAIProvider());
}

export async function runEvidenceWorker(scanId: string): Promise<number> {
  const verifiedFindings = await FindingModel.find({
    scanId,
    status: FindingStatus.VERIFIED,
  });

  const aiService = getAiService();
  let enriched = 0;

  for (const finding of verifiedFindings) {
    try {
      const analysis = await aiService.analyzeFinding({
        ruleId: finding.ruleId,
        ruleName: finding.title,
        cwe: finding.cwe,
        owasp: finding.owasp,
        endpoint: finding.endpoint,
        method: finding.method,
        parameter: finding.parameter,
        rawRequest: { method: finding.method, url: finding.endpoint, headers: {} },
        rawResponse: { statusCode: 200, headers: {}, body: finding.description },
      });

      if (analysis) {
        finding.impact = analysis.technicalImpact;
        finding.remediation = `${finding.remediation}\n\n[AI Guidance]: ${analysis.tailoredRemediation}`;
        await finding.save();
        enriched++;
      }
    } catch (err) {
      logger.debug({ findingId: finding._id, error: (err as Error).message }, 'AI evidence enrichment skipped');
    }
  }

  return enriched;
}
