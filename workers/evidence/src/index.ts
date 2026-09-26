import { FindingModel, EvidenceModel } from '@securityscan/database';
import { FindingStatus } from '@securityscan/contracts';
import { AISecurityService, MockAIProvider, OpenAIProvider, GeminiProvider, AnthropicProvider } from '@securityscan/ai';
import { createStorageProvider, type StorageProvider } from '@securityscan/storage';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('worker-evidence');

function getAiService(): AISecurityService {
  if (process.env['OPENAI_API_KEY']) return new AISecurityService(new OpenAIProvider());
  if (process.env['GEMINI_API_KEY']) return new AISecurityService(new GeminiProvider());
  if (process.env['ANTHROPIC_API_KEY']) return new AISecurityService(new AnthropicProvider());
  return new AISecurityService(new MockAIProvider());
}

export async function runEvidenceWorker(
  scanId: string,
  options?: { storageProvider?: StorageProvider },
): Promise<number> {
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

  // Persist all scan evidence artifacts to object storage
  try {
    const storage = options?.storageProvider ?? createStorageProvider();
    const evidences = await EvidenceModel.find({ scanId });

    for (const evidence of evidences) {
      if (!evidence.storageKey) {
        try {
          const storageKey = `evidence/${scanId}/${evidence._id}.json`;
          const payload = JSON.stringify(
            {
              evidenceId: evidence._id,
              findingId: evidence.findingId,
              scanId: evidence.scanId,
              request: evidence.request,
              response: evidence.response,
              endpoint: evidence.endpoint,
              parameter: evidence.parameter,
              authContext: evidence.authContext,
              comparisonResults: evidence.comparisonResults,
              relevantHeaders: evidence.relevantHeaders,
              relevantResponseData: evidence.relevantResponseData,
              timestamp: evidence.timestamp,
            },
            null,
            2,
          );

          await storage.putObject(storageKey, payload, 'application/json', {
            scanId: scanId.toString(),
            findingId: evidence.findingId.toString(),
          });

          const presignedUrl = await storage.getPresignedUrl(storageKey, 86400);
          evidence.storageKey = storageKey;
          evidence.storageUrl = presignedUrl;
          await evidence.save();
        } catch (uploadErr: any) {
          logger.warn(
            { evidenceId: evidence._id, err: uploadErr?.message },
            'Failed to upload individual evidence artifact to storage provider',
          );
        }
      }
    }
  } catch (storageInitErr: any) {
    logger.warn({ scanId, err: storageInitErr?.message }, 'Failed to initialize storage provider for evidence worker');
  }

  return enriched;
}
