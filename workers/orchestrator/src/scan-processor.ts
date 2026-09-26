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
