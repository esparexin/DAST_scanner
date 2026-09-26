import type { SecureHttpClient } from '@securityscan/http-client';
import { Crawler } from '@securityscan/crawler';
import { DetectionEngine, type SecurityCheck, type CheckContext } from '@securityscan/detection-engine';
import { VerificationEngine } from '@securityscan/verification-engine';
import { AISecurityService } from '@securityscan/ai';
import type { AIProvider } from '@securityscan/ai';
import { EvidenceCollector } from '@securityscan/evidence-engine';
import { RiskClassifier } from '@securityscan/risk-engine';
import { SecurityKnowledgeBase } from '@securityscan/knowledge-base';
import { ScanStateMachine } from '@securityscan/scanner-core';
import {
  PayloadRegistry,
  ReflectionContextAnalyzer,
  loadDefaultCatalogs,
  CatalogOverrideManager,
  type OrganizationOverrides,
} from '@securityscan/payload-engine';
import { SqlInjectionChecks } from '@securityscan/check-injection';
import { XssChecks } from '@securityscan/check-xss';
import { PathTraversalChecks } from '@securityscan/check-path-traversal';
import { SsrfCandidateChecks } from '@securityscan/check-ssrf';
import { CsrfChecks } from '@securityscan/check-csrf';
import { FileUploadChecks } from '@securityscan/check-file-upload';
import { ForcedBrowsingChecks } from '@securityscan/check-access-control';
import { MassAssignmentChecks } from '@securityscan/check-api';
import { JwtSecurityChecks, OAuthSecurityChecks } from '@securityscan/check-authentication';
import { BolaChecks, BflaChecks } from '@securityscan/check-authorization';
import { CleartextChecks } from '@securityscan/check-cryptography';
import {
  SecurityHeaderChecks,
  CookieChecks,
  CorsChecks,
  InfoDisclosureChecks,
} from '@securityscan/check-misconfiguration';
import {
  HttpMethod,
  FindingStatus,
  ScanStatus,
  type IFinding,
  Severity,
  Confidence,
  DetectionCategory,
} from '@securityscan/contracts';
import { ScanModel, TargetModel } from '@securityscan/database';
import { processPassiveAnalysis } from '@securityscan/worker-passive-analysis';
import { runActiveTestingWorker } from '@securityscan/worker-active-testing';
import { runApiTestingWorker } from '@securityscan/worker-api-testing';
import { runVerificationWorker } from '@securityscan/worker-verification';
import { runEvidenceWorker } from '@securityscan/worker-evidence';
import { runReportingWorker } from '@securityscan/worker-reporting';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('scan-processor');

export interface ScanJob {
  scanId: string;
  targetUrl: string;
  scopePatterns: string[];
  profile: string;
  organizationOverrides?: OrganizationOverrides;
}

export async function processScan(scanId: string): Promise<void> {
  const scan = await ScanModel.findById(scanId);
  if (!scan || scan.status === ScanStatus.CANCELLED) return;

  const target = await TargetModel.findById(scan.targetId);
  if (!target || target.authorization !== 'AUTHORIZED') {
    await ScanModel.findByIdAndUpdate(scanId, {
      status: ScanStatus.FAILED,
      failureReason: 'Target is not AUTHORIZED for scanning',
    });
    return;
  }

  try {
    await ScanModel.findByIdAndUpdate(scanId, { status: ScanStatus.CRAWLING, startedAt: new Date() });
    await processPassiveAnalysis(scanId);
    await runActiveTestingWorker(scanId);
    await runApiTestingWorker(scanId);
    await runVerificationWorker(scanId);
    await runEvidenceWorker(scanId);
    await runReportingWorker(scanId);
    await ScanModel.findByIdAndUpdate(scanId, { status: ScanStatus.COMPLETED, completedAt: new Date() });
  } catch (err: any) {
    logger.error({ scanId, err }, 'Scan processing failed');
    await ScanModel.findByIdAndUpdate(scanId, {
      status: ScanStatus.FAILED,
      failureReason: err?.message ?? 'Internal scan execution error',
    });
  }
}

export class ScanProcessor {
  private readonly httpClient: SecureHttpClient;
  private readonly aiService?: AISecurityService;

  constructor(httpClient: SecureHttpClient, aiService?: AISecurityService, _aiProvider?: AIProvider) {
    this.httpClient = httpClient;
    this.aiService = aiService;
  }

  async process(job: ScanJob): Promise<IFinding[]> {
    const sm = new ScanStateMachine(ScanStatus.CREATED);
    const findings: IFinding[] = [];

    // Initialize payload engine with catalogs and optional org overrides
    const registry = new PayloadRegistry();
    loadDefaultCatalogs(registry);
    if (job.organizationOverrides) {
      const overrideResult = CatalogOverrideManager.applyOverrides(registry, job.organizationOverrides);
      logger.info(
        { scanId: job.scanId, disabled: overrideResult.applied },
        'Applied organization payload overrides',
      );
    }

    const reflectionAnalyzer = new ReflectionContextAnalyzer(this.httpClient);

    try {
      // Phase 1: Crawl
      sm.transition(ScanStatus.CRAWLING);
      logger.info({ scanId: job.scanId, target: job.targetUrl }, 'Starting crawl phase');

      const crawler = new Crawler(this.httpClient);
      const discovered = await crawler.crawl(job.targetUrl, 3);

      // Phase 2: Reflection Pre-Analysis
      logger.info({ scanId: job.scanId, endpoints: discovered.length }, 'Analyzing reflection contexts');
      const reflectionMap = new Map<string, string>();
      for (const res of discovered) {
        try {
          const url = new URL(res.url);
          for (const [paramName] of url.searchParams.entries()) {
            const analysis = await reflectionAnalyzer.analyzeReflection(res.url, paramName);
            if (analysis.reflected) {
              reflectionMap.set(`${res.url}:${paramName}`, analysis.context);
              logger.debug(
                { endpoint: res.url, paramName, context: analysis.context },
                'Reflection context identified',
              );
            }
          }
        } catch {
          // Non-critical analysis
        }
      }

      // Phase 3: Active Testing
      logger.info({ scanId: job.scanId, endpoints: discovered.length }, 'Starting active testing');

      const engine = new DetectionEngine();

      // Initialize checks with shared registry so they use curated catalogs
      const allChecks: SecurityCheck[] = [
        ...SqlInjectionChecks.getChecks(registry),
        ...XssChecks.getChecks(registry),
        ...PathTraversalChecks.getChecks(registry),
        ...SsrfCandidateChecks.getChecks(),
        ...CsrfChecks.getChecks(),
        ...FileUploadChecks.getChecks(),
        ...ForcedBrowsingChecks.getChecks(),
        ...MassAssignmentChecks.getChecks(),
        ...JwtSecurityChecks.getChecks(),
        ...OAuthSecurityChecks.getChecks(),
        ...BolaChecks.getChecks(),
        ...BflaChecks.getChecks(),
        ...CleartextChecks.getChecks(),
        ...SecurityHeaderChecks.getChecks(),
        ...CookieChecks.getChecks(),
        ...CorsChecks.getChecks(),
        ...InfoDisclosureChecks.getChecks(),
      ];

      engine.registerAll(allChecks);

      for (const res of discovered) {
        const endpoint = res.url;
        const ctx: CheckContext = {
          scanId: job.scanId,
          targetId: '',
          projectId: '',
          baseUrl: job.targetUrl,
          endpoint: {
            id: `ep-${job.scanId}-${endpoint}`,
            scanId: job.scanId,
            targetId: '',
            projectId: '',
            url: endpoint,
            path: new URL(endpoint).pathname,
            method: HttpMethod.GET,
            parameters: [],
            headers: {},
            requiresAuth: false,
            discoverySource: 'crawler',
            createdAt: new Date(),
          },
          httpClient: this.httpClient,
        };

        const results = await engine.runAll(ctx);

        for (const result of results) {
          // Phase 4: Verification
          const verificationEngine = new VerificationEngine(this.httpClient);
          const verification = await verificationEngine.verify({
            findingId: result.ruleId,
            endpoint: result.endpoint ?? endpoint,
            method: result.method ?? 'GET',
            parameter: result.parameter,
            expectedSignature:
              result.evidence?.response?.body?.toString().slice(0, 100),
          });

          if (!verification.verified) {
            logger.info({ ruleId: result.ruleId }, 'Finding not verified, skipping');
            continue;
          }

          // Phase 5: Evidence Collection
          const evidenceCollector = new EvidenceCollector();
          evidenceCollector.collect({
            request: result.evidence?.request ?? { method: 'GET', url: endpoint, headers: {} },
            response: result.evidence?.response ?? {
              statusCode: 0,
              headers: {},
              body: '',
              responseTime: 0,
            },
            endpoint,
            authContext: 'ANONYMOUS',
          });

          // Phase 6: Risk Classification
          const riskClassifier = new RiskClassifier();
          const risk = riskClassifier.classify(
            result.severity ?? Severity.MEDIUM,
            result.confidence ?? Confidence.LOW,
          );

          // Phase 7: Knowledge Base Enrichment
          const cweId = result.cwe?.[0];
          const cweInfo = cweId ? SecurityKnowledgeBase.getCwe(cweId) : undefined;
          const owaspId = result.owasp?.[0];
          const owaspInfo = owaspId ? SecurityKnowledgeBase.getOwaspTop10(owaspId) : undefined;

          // Phase 8: AI Enrichment (optional)
          let aiAnalysis;
          if (this.aiService) {
            try {
              aiAnalysis = await this.aiService.analyzeFinding({
                ruleId: result.ruleId,
                ruleName: result.title ?? result.ruleId,
                cwe: result.cwe ?? [],
                owasp: result.owasp ?? [],
                endpoint: result.endpoint ?? endpoint,
                method: result.method ?? 'GET',
                parameter: result.parameter,
                rawRequest: result.evidence?.request ?? { method: 'GET', url: endpoint, headers: {} },
                rawResponse: result.evidence?.response ?? { statusCode: 200, headers: {}, responseTime: 0 },
              });
            } catch (err) {
              logger.warn({ error: err }, 'AI enrichment failed, continuing without');
            }
          }

          const finding: IFinding = {
            id: `finding-${job.scanId}-${findings.length + 1}`,
            scanId: job.scanId,
            projectId: '',
            targetId: '',
            ruleId: result.ruleId,
            title: result.title ?? result.ruleId,
            description: result.description ?? '',
            impact: result.impact ?? '',
            severity: risk.severity,
            confidence: verification.confidence as any,
            category: result.category ?? DetectionCategory.MISCONFIGURATION,
            endpoint: result.endpoint ?? endpoint,
            method: result.method ?? 'GET',
            parameter: result.parameter,
            evidenceIds: [],
            remediation: result.remediation,
            cwe: result.cwe ?? [],
            owasp: result.owasp ?? [],
            apiOwasp: result.apiOwasp ?? [],
            cvssVector: (result as any).cvssVector,
            cvssScore: (result as any).cvssScore,
            wstg: (result as any).wstg ?? [],
            asvs: (result as any).asvs ?? [],
            references: result.references ?? [],
            deduplicationKey: `${job.scanId}:${result.ruleId}:${endpoint}`,
            firstDetectedAt: new Date(),
            lastDetectedAt: new Date(),
            status: FindingStatus.VERIFIED,
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          findings.push(finding);

          logger.info(
            {
              findingId: finding.id,
              ruleId: finding.ruleId,
              severity: finding.severity,
              confidence: finding.confidence,
              cwe: cweInfo?.name,
              owasp: owaspInfo?.name,
              aiExploitability: aiAnalysis?.falsePositiveLikelihood,
            },
            'Finding confirmed and enriched',
          );
        }
      }

      sm.transition(ScanStatus.COMPLETED);

      logger.info(
        {
          scanId: job.scanId,
          totalFindings: findings.length,
          catalogVersion: registry.getCatalogVersion(),
          activePayloads: registry.getAll().filter((p) => p.status === 'ACTIVE').length,
        },
        'Scan completed successfully',
      );
    } catch (error) {
      sm.transition(ScanStatus.FAILED);
      logger.error({ scanId: job.scanId, error }, 'Scan failed');
      throw error;
    }

    return findings;
  }
}
