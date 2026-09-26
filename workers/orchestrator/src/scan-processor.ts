import type { SecureHttpClient } from '@securityscan/http-client';
import { Crawler } from '@securityscan/crawler';
import { DetectionEngine, type SecurityCheck, type CheckContext } from '@securityscan/detection-engine';
import { VerificationEngine } from '@securityscan/verification-engine';
import { AISecurityService } from '@securityscan/ai';
import type { AIProvider } from '@securityscan/ai';
import { EvidenceCollector } from '@securityscan/evidence-engine';
import { RiskClassifier } from '@securityscan/risk-engine';
import { SecurityKnowledgeBase } from '@securityscan/knowledge-base';
import {
  ScanStateMachine,
  SCAN_EVENTS_CHANNEL,
  createRedisClient,
  formatScanProgressEvent,
  dispatchWebhook,
} from '@securityscan/scanner-core';
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
  WebhookEvent,
} from '@securityscan/contracts';
import {
  ScanModel,
  TargetModel,
  ProjectModel,
  MembershipModel,
  FindingModel,
  WebhookSubscriptionModel,
} from '@securityscan/database';
import { processPassiveAnalysis } from '@securityscan/worker-passive-analysis';
import { runActiveTestingWorker } from '@securityscan/worker-active-testing';
import { runApiTestingWorker } from '@securityscan/worker-api-testing';
import { runVerificationWorker } from '@securityscan/worker-verification';
import { runEvidenceWorker } from '@securityscan/worker-evidence';
import { runReportingWorker } from '@securityscan/worker-reporting';
import { scanMetrics } from '@securityscan/metrics';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('scan-processor');

let redisPublisher: ReturnType<typeof createRedisClient> | null = null;
function getPublisher() {
  if (!redisPublisher) {
    redisPublisher = createRedisClient();
    redisPublisher.connect().catch((err: unknown) => {
      logger.warn({ err }, 'Failed to connect Redis publisher for scan events');
    });
  }
  return redisPublisher;
}

async function emitProgress(
  scanId: string,
  phase: ScanStatus,
  extra?: { message?: string; endpointsDiscovered?: number; findingsTotal?: number; findingsConfirmed?: number },
): Promise<void> {
  try {
    const pub = getPublisher();
    const event = formatScanProgressEvent(scanId, phase, extra);
    await pub.publish(SCAN_EVENTS_CHANNEL, JSON.stringify(event));
  } catch (err: unknown) {
    logger.warn({ scanId, phase, err }, 'Failed to publish scan progress event');
  }
}

async function triggerScanWebhooks(
  scanId: string,
  event: WebhookEvent,
  data: Record<string, unknown>,
): Promise<void> {
  try {
    const scan = await ScanModel.findById(scanId);
    if (!scan) return;
    const project = await ProjectModel.findById(scan.projectId);
    if (!project) return;
    const membership = await MembershipModel.findOne({ userId: project.ownerId });
    if (!membership) return;

    const target = await TargetModel.findById(scan.targetId);
    const targetUrl = target?.baseUrl;

    const subscriptions = await WebhookSubscriptionModel.find({
      organizationId: membership.organizationId,
      enabled: true,
      events: event,
    });

    if (!subscriptions || subscriptions.length === 0) return;

    const payload = {
      event,
      timestamp: new Date().toISOString(),
      organizationId: membership.organizationId.toString(),
      scanId,
      targetUrl,
      data,
    };

    await Promise.allSettled(
      subscriptions.map((sub) =>
        dispatchWebhook(
          { url: sub.url, secret: sub.secret, format: sub.format as any },
          payload,
        ),
      ),
    );
  } catch (err: any) {
    logger.warn({ scanId, event, err: err?.message }, 'Failed to trigger scan webhooks');
  }
}

export interface ScanJob {
  scanId: string;
  targetUrl: string;
  scopePatterns: string[];
  profile: string;
  organizationOverrides?: OrganizationOverrides;
}

export async function processScan(scanId: string, options?: { traceId?: string }): Promise<void> {
  const scan = await ScanModel.findById(scanId);
  if (!scan || scan.status === ScanStatus.CANCELLED) return;

  const traceId = options?.traceId;
  const target = await TargetModel.findById(scan.targetId);
  if (!target || target.authorization !== 'AUTHORIZED') {
    await ScanModel.findByIdAndUpdate(scanId, {
      status: ScanStatus.FAILED,
      failureReason: 'Target is not AUTHORIZED for scanning',
    });
    await emitProgress(scanId, ScanStatus.FAILED, { message: 'Target is not AUTHORIZED for scanning' });
    return;
  }

  const scanStart = Date.now();
  scanMetrics.incrementCounter('securityscan_scans_total');
  scanMetrics.incrementGauge('securityscan_scans_active');

  const recordPhase = async (
    phase: ScanStatus,
    message: string,
    action: () => Promise<unknown>,
  ) => {
    const phaseStart = Date.now();
    await ScanModel.findByIdAndUpdate(scanId, {
      status: phase,
      'progress.phase': phase,
    });
    await emitProgress(scanId, phase, { message });
    await action();
    const phaseDuration = (Date.now() - phaseStart) / 1000;
    scanMetrics.observeHistogram('securityscan_phase_duration_seconds', phaseDuration, {
      phase,
    });
  };

  try {
    const checkCancelled = async () => {
      const s = await ScanModel.findById(scanId);
      if (s?.status === ScanStatus.CANCELLED) {
        throw new Error('Scan cancelled by user');
      }
    };

    await checkCancelled();
    await ScanModel.findByIdAndUpdate(scanId, {
      startedAt: new Date(),
    });
    await recordPhase(ScanStatus.CRAWLING, 'Crawler initiated', async () => {});

    await checkCancelled();
    await recordPhase(ScanStatus.PASSIVE_ANALYSIS, 'Running passive security checks', async () => {
      await processPassiveAnalysis(scanId);
    });

    await checkCancelled();
    await recordPhase(ScanStatus.ACTIVE_TESTING, 'Running active payload checks', async () => {
      await runActiveTestingWorker(scanId);
    });

    await checkCancelled();
    await recordPhase(ScanStatus.API_TESTING, 'Running API security checks', async () => {
      await runApiTestingWorker(scanId);
    });

    await checkCancelled();
    await recordPhase(ScanStatus.VERIFYING, 'Verifying findings', async () => {
      await runVerificationWorker(scanId);
    });

    await checkCancelled();
    await recordPhase(ScanStatus.EVIDENCE_COLLECTION, 'Collecting proof and evidence', async () => {
      await runEvidenceWorker(scanId);
    });

    await checkCancelled();
    await recordPhase(ScanStatus.REPORTING, 'Generating report', async () => {
      await runReportingWorker(scanId);
    });

    await ScanModel.findByIdAndUpdate(scanId, {
      status: ScanStatus.COMPLETED,
      'progress.phase': ScanStatus.COMPLETED,
      completedAt: new Date(),
    });
    await emitProgress(scanId, ScanStatus.COMPLETED, { message: 'Scan finished successfully' });

    scanMetrics.incrementCounter('securityscan_scans_completed_total');
    scanMetrics.incrementGauge('securityscan_scans_active', {}, -1);
    const totalDuration = (Date.now() - scanStart) / 1000;
    scanMetrics.observeHistogram('securityscan_scan_duration_seconds', totalDuration);

    logger.info({ scanId, traceId, durationSeconds: totalDuration }, 'Scan execution completed successfully');

    // Dispatch webhook notifications
    await triggerScanWebhooks(scanId, WebhookEvent.SCAN_COMPLETED, {
      status: ScanStatus.COMPLETED,
      durationSeconds: totalDuration,
      message: 'Scan execution completed successfully',
    });

    try {
      const verifiedFindings = await FindingModel.find({
        scanId,
        severity: { $in: [Severity.CRITICAL, Severity.HIGH] },
        status: FindingStatus.VERIFIED,
      });
      if (verifiedFindings.length > 0) {
        const hasCritical = verifiedFindings.some((f) => f.severity === Severity.CRITICAL);
        const eventType = hasCritical ? WebhookEvent.FINDING_CRITICAL : WebhookEvent.FINDING_HIGH;
        await triggerScanWebhooks(scanId, eventType, {
          totalFindings: verifiedFindings.length,
          criticalCount: verifiedFindings.filter((f) => f.severity === Severity.CRITICAL).length,
          highCount: verifiedFindings.filter((f) => f.severity === Severity.HIGH).length,
        });
      }
    } catch (findingErr: unknown) {
      logger.warn({ scanId, err: findingErr }, 'Failed checking verified findings for webhook alerts');
    }
  } catch (err: any) {
    scanMetrics.incrementGauge('securityscan_scans_active', {}, -1);
    if (err?.message === 'Scan cancelled by user') {
      logger.info({ scanId, traceId }, 'Scan terminated due to cancellation');
      await emitProgress(scanId, ScanStatus.CANCELLED, { message: 'Scan cancelled by user' });
      return;
    }

    scanMetrics.incrementCounter('securityscan_scans_failed_total');
    logger.error({ scanId, traceId, err }, 'Scan processing failed');
    await ScanModel.findByIdAndUpdate(scanId, {
      status: ScanStatus.FAILED,
      failureReason: err?.message ?? 'Internal scan execution error',
    });
    await emitProgress(scanId, ScanStatus.FAILED, { message: err?.message ?? 'Internal scan execution error' });

    await triggerScanWebhooks(scanId, WebhookEvent.SCAN_FAILED, {
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
