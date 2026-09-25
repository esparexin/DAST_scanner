import type { SecureHttpClient } from '@securityscan/http-client';
import { Crawler } from '@securityscan/crawler';
import { DetectionEngine, type SecurityCheck, type CheckContext } from '@securityscan/detection-engine';
import { VerificationEngine } from '@securityscan/verification-engine';
import { AISecurityService, AIPayloadAdvisor } from '@securityscan/ai';
import type { AIProvider } from '@securityscan/ai';
import { FindingEngine } from '@securityscan/finding-engine';
import { EvidenceCollector } from '@securityscan/evidence-engine';
import { RiskClassifier } from '@securityscan/risk-engine';
import { SecurityKnowledgeBase } from '@securityscan/knowledge-base';
import { ScanStateMachine, ScanState } from '@securityscan/scanner-core';
import {
  PayloadRegistry,
  PayloadSelector,
  MutationPipeline,
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
import { JwtChecks, OAuthChecks } from '@securityscan/check-authentication';
import { BolaChecks, BflaChecks } from '@securityscan/check-authorization';
import { CleartextChecks } from '@securityscan/check-cryptography';
import {
  SecurityHeaderChecks,
  CookieChecks,
  CorsChecks,
  InfoDisclosureChecks,
} from '@securityscan/check-misconfiguration';
import { HttpMethod, type IFinding, Severity, Confidence, DetectionCategory, ScanProfile } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('scan-processor');

export interface ScanJob {
  scanId: string;
  targetUrl: string;
  scopePatterns: string[];
  profile: string;
  organizationOverrides?: OrganizationOverrides;
}

export class ScanProcessor {
  private readonly httpClient: SecureHttpClient;
  private readonly aiService?: AISecurityService;
  private readonly aiProvider?: AIProvider;

  constructor(httpClient: SecureHttpClient, aiService?: AISecurityService, aiProvider?: AIProvider) {
    this.httpClient = httpClient;
    this.aiService = aiService;
    this.aiProvider = aiProvider;
  }

  async process(job: ScanJob): Promise<IFinding[]> {
    const sm = new ScanStateMachine(job.scanId);
    const findings: IFinding[] = [];
    const kb = new SecurityKnowledgeBase();

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

    const selector = new PayloadSelector(registry);
    const reflectionAnalyzer = new ReflectionContextAnalyzer(this.httpClient);

    // AI payload advisor (optional)
    let payloadAdvisor: AIPayloadAdvisor | undefined;
    if (this.aiProvider) {
      payloadAdvisor = new AIPayloadAdvisor(this.aiProvider);
    }

    try {
      // Phase 1: Crawl
      sm.transition(ScanState.CRAWLING);
      logger.info({ scanId: job.scanId, target: job.targetUrl }, 'Starting crawl phase');

      const crawler = new Crawler(this.httpClient);
      const discovered = await crawler.crawl(job.targetUrl, { maxDepth: 3, maxPages: 100 });

      // Phase 2: Reflection Pre-Analysis
      logger.info({ scanId: job.scanId, endpoints: discovered.length }, 'Analyzing reflection contexts');
      const reflectionMap = new Map<string, string>();
      for (const endpoint of discovered) {
        try {
          const url = new URL(endpoint);
          for (const [paramName] of url.searchParams.entries()) {
            const analysis = await reflectionAnalyzer.analyzeReflection(endpoint, paramName);
            if (analysis.reflected) {
              reflectionMap.set(`${endpoint}:${paramName}`, analysis.context);
              logger.debug(
                { endpoint, paramName, context: analysis.context },
                'Reflection context identified',
              );
            }
          }
        } catch {
          // Non-critical analysis
        }
      }

      // Phase 3: Active Testing
      sm.transition(ScanState.TESTING);
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
        ...JwtChecks.getChecks(),
        ...OAuthChecks.getChecks(),
        ...BolaChecks.getChecks(),
        ...BflaChecks.getChecks(),
        ...CleartextChecks.getChecks(),
        ...SecurityHeaderChecks.getChecks(),
        ...CookieChecks.getChecks(),
        ...CorsChecks.getChecks(),
        ...InfoDisclosureChecks.getChecks(),
      ];

      for (const check of allChecks) {
        engine.registerCheck(check);
      }

      for (const endpoint of discovered) {
        const ctx: CheckContext = {
          endpoint: { url: endpoint, method: HttpMethod.GET },
          httpClient: this.httpClient,
        };

        const results = await engine.run(ctx);

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
          const evidence = evidenceCollector.collect({
            request: result.evidence?.request ?? { method: 'GET', url: endpoint, headers: {} },
            response: result.evidence?.response ?? {
              statusCode: 0,
              headers: {},
              body: '',
              responseTime: 0,
            },
          });

          // Phase 6: Risk Classification
          const riskClassifier = new RiskClassifier();
          const risk = riskClassifier.classify({
            severity: result.severity ?? Severity.MEDIUM,
            confidence: result.confidence ?? Confidence.LOW,
            category: result.category ?? DetectionCategory.MISCONFIGURATION,
          });

          // Phase 7: Knowledge Base Enrichment
          const cweId = result.cwe?.[0];
          const cweInfo = cweId ? kb.lookupCWE(cweId) : undefined;
          const owaspId = result.owasp?.[0];
          const owaspInfo = owaspId ? kb.lookupOwaspTop10(owaspId) : undefined;

          // Phase 8: AI Enrichment (optional)
          let aiAnalysis;
          if (this.aiService) {
            try {
              aiAnalysis = await this.aiService.analyzeFinding({
                findingTitle: result.title ?? result.ruleId,
                findingDescription: result.description ?? '',
                category: result.category ?? 'UNKNOWN',
                severity: result.severity ?? 'MEDIUM',
                endpoint: result.endpoint ?? endpoint,
                method: result.method ?? 'GET',
                parameter: result.parameter,
                cwe: result.cwe,
                owasp: result.owasp,
              });
            } catch (err) {
              logger.warn({ error: err }, 'AI enrichment failed, continuing without');
            }
          }

          const finding: IFinding = {
            id: `finding-${job.scanId}-${findings.length + 1}`,
            scanId: job.scanId,
            ruleId: result.ruleId,
            title: result.title ?? result.ruleId,
            description: result.description ?? '',
            severity: risk.adjustedSeverity,
            confidence: verification.confidence as any,
            category: result.category ?? DetectionCategory.MISCONFIGURATION,
            endpoint: result.endpoint ?? endpoint,
            method: result.method ?? 'GET',
            parameter: result.parameter,
            evidence: evidence as any,
            remediation: result.remediation,
            cwe: result.cwe ?? [],
            owasp: result.owasp ?? [],
            cvssVector: (result as any).cvssVector,
            cvssScore: (result as any).cvssScore,
            wstg: (result as any).wstg ?? [],
            asvs: (result as any).asvs ?? [],
            status: 'OPEN',
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
              aiExploitability: aiAnalysis?.exploitability,
            },
            'Finding confirmed and enriched',
          );
        }
      }

      sm.transition(ScanState.ANALYZING);
      sm.transition(ScanState.COMPLETED);

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
      sm.transition(ScanState.FAILED);
      logger.error({ scanId: job.scanId, error }, 'Scan failed');
      throw error;
    }

    return findings;
  }
}
