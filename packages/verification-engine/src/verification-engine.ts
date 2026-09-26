import type { SecureHttpClient } from '@securityscan/http-client';
import type { IPayloadDefinition, MaterializedTestVariant } from '@securityscan/payload-engine';
import { HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('verification-engine');

export interface VerificationRequest {
  findingId: string;
  endpoint: string;
  method: string;
  parameter?: string;
  originalPayload?: string;
  expectedSignature?: string;
  replayAttempts?: number;
}

export interface PayloadVerificationRequest {
  findingId: string;
  endpoint: string;
  method: string;
  parameter: string;
  payloadDefinition: IPayloadDefinition;
  variant: MaterializedTestVariant;
}

export interface VerificationResult {
  findingId: string;
  verified: boolean;
  replayCount: number;
  consistentResponse: boolean;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH' | 'CONFIRMED';
  strategy: string;
}

export class VerificationEngine {
  private readonly httpClient: SecureHttpClient;

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Legacy verification: generic replay-based confirmation.
   */
  async verify(request: VerificationRequest): Promise<VerificationResult> {
    const attempts = request.replayAttempts ?? 2;
    let successCount = 0;

    for (let i = 0; i < attempts; i++) {
      try {
        const response = await this.httpClient.request({
          method: request.method as HttpMethod,
          url: request.endpoint,
        });

        if (request.expectedSignature && response.body.includes(request.expectedSignature)) {
          successCount++;
        } else if (response.statusCode < 500) {
          successCount++;
        }
      } catch (error) {
        logger.warn({ findingId: request.findingId, attempt: i }, 'Verification replay failed');
      }
    }

    const ratio = successCount / attempts;

    return {
      findingId: request.findingId,
      verified: ratio >= 0.5,
      replayCount: attempts,
      consistentResponse: ratio >= 1.0,
      confidence: ratio >= 1.0 ? 'CONFIRMED' : ratio >= 0.5 ? 'HIGH' : 'LOW',
      strategy: 'LEGACY_REPLAY',
    };
  }

  /**
   * Payload-aware verification: uses the payload definition's declared verification strategy.
   */
  async verifyWithPayload(request: PayloadVerificationRequest): Promise<VerificationResult> {
    const { payloadDefinition, variant, findingId, endpoint, method, parameter } = request;
    const strategy = payloadDefinition.verification.strategy;
    const attempts = payloadDefinition.verification.replayAttemptsRequired;

    logger.info(
      { findingId, strategy, attempts, payloadId: payloadDefinition.id },
      'Starting payload-aware verification',
    );

    switch (strategy) {
      case 'REPLAY_PROBE_CONFIRMATION':
        return this.replayProbeConfirmation(findingId, endpoint, method, parameter, variant, payloadDefinition, attempts);

      case 'TOKEN_EQUIVALENCE':
        return this.tokenEquivalenceVerification(findingId, endpoint, method, parameter, variant, attempts);

      case 'STATUS_CODE_STABILITY':
        return this.statusCodeStabilityVerification(findingId, endpoint, method, parameter, variant, payloadDefinition, attempts);

      case 'TIMING_CONFIRMATION':
        return this.timingConfirmationVerification(findingId, endpoint, method, parameter, variant, payloadDefinition, attempts);

      case 'BEHAVIORAL_REPLAY':
        return this.replayProbeConfirmation(findingId, endpoint, method, parameter, variant, payloadDefinition, attempts);

      default:
        return this.replayProbeConfirmation(findingId, endpoint, method, parameter, variant, payloadDefinition, attempts);
    }
  }

  /**
   * REPLAY_PROBE_CONFIRMATION: Re-send the exact same probe N times.
   * Confirm the same error signatures appear consistently.
   */
  private async replayProbeConfirmation(
    findingId: string,
    endpoint: string,
    method: string,
    parameter: string,
    variant: MaterializedTestVariant,
    payload: IPayloadDefinition,
    attempts: number,
  ): Promise<VerificationResult> {
    let matchCount = 0;
    const url = new URL(endpoint);
    url.searchParams.set(parameter, variant.finalValue);
    const fullUrl = url.toString();

    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this.httpClient.request({
          method: method as HttpMethod,
          url: fullUrl,
        });

        const signatures = payload.detection.errorSignatures ?? [];
        const bodyLower = res.body.toLowerCase();
        const matched = signatures.some((sig) => bodyLower.includes(sig.toLowerCase()));
        if (matched) matchCount++;
      } catch {
        logger.warn({ findingId, attempt: i }, 'Replay probe failed');
      }
    }

    const ratio = matchCount / attempts;
    return {
      findingId,
      verified: ratio >= 0.5,
      replayCount: attempts,
      consistentResponse: ratio >= 1.0,
      confidence: ratio >= 1.0 ? 'CONFIRMED' : ratio >= 0.5 ? 'HIGH' : 'LOW',
      strategy: 'REPLAY_PROBE_CONFIRMATION',
    };
  }

  /**
   * TOKEN_EQUIVALENCE: Re-send the canary-bearing probe and verify exact canary token appears in response.
   */
  private async tokenEquivalenceVerification(
    findingId: string,
    endpoint: string,
    method: string,
    parameter: string,
    variant: MaterializedTestVariant,
    attempts: number,
  ): Promise<VerificationResult> {
    if (!variant.canaryToken) {
      return {
        findingId,
        verified: false,
        replayCount: 0,
        consistentResponse: false,
        confidence: 'LOW',
        strategy: 'TOKEN_EQUIVALENCE',
      };
    }

    let matchCount = 0;
    const url = new URL(endpoint);
    url.searchParams.set(parameter, variant.finalValue);
    const fullUrl = url.toString();

    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this.httpClient.request({
          method: method as HttpMethod,
          url: fullUrl,
        });

        const expected = variant.finalValue || variant.canaryToken;
        if (res.body.includes(expected)) {
          matchCount++;
        }
      } catch {
        logger.warn({ findingId, attempt: i }, 'Token equivalence replay failed');
      }
    }

    const ratio = matchCount / attempts;
    return {
      findingId,
      verified: ratio >= 0.5,
      replayCount: attempts,
      consistentResponse: ratio >= 1.0,
      confidence: ratio >= 1.0 ? 'CONFIRMED' : ratio >= 0.5 ? 'HIGH' : 'LOW',
      strategy: 'TOKEN_EQUIVALENCE',
    };
  }

  /**
   * STATUS_CODE_STABILITY: Verify that the same status code pattern (2xx success where it should fail) is consistent.
   */
  private async statusCodeStabilityVerification(
    findingId: string,
    endpoint: string,
    method: string,
    parameter: string,
    variant: MaterializedTestVariant,
    payload: IPayloadDefinition,
    attempts: number,
  ): Promise<VerificationResult> {
    let matchCount = 0;
    const expectedCodes = payload.detection.expectedStatusCodes ?? [200];
    const url = new URL(endpoint);
    url.searchParams.set(parameter, variant.finalValue);
    const fullUrl = url.toString();

    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this.httpClient.request({
          method: method as HttpMethod,
          url: fullUrl,
        });

        if (expectedCodes.includes(res.statusCode)) {
          matchCount++;
        }
      } catch {
        logger.warn({ findingId, attempt: i }, 'Status code stability replay failed');
      }
    }

    const ratio = matchCount / attempts;
    return {
      findingId,
      verified: ratio >= 0.5,
      replayCount: attempts,
      consistentResponse: ratio >= 1.0,
      confidence: ratio >= 1.0 ? 'CONFIRMED' : ratio >= 0.5 ? 'HIGH' : 'LOW',
      strategy: 'STATUS_CODE_STABILITY',
    };
  }

  /**
   * TIMING_CONFIRMATION: Verify that injected time delays produce measurable latency deltas.
   */
  private async timingConfirmationVerification(
    findingId: string,
    endpoint: string,
    method: string,
    parameter: string,
    variant: MaterializedTestVariant,
    payload: IPayloadDefinition,
    attempts: number,
  ): Promise<VerificationResult> {
    const thresholdMs = payload.detection.timingThresholdMs ?? 3000;
    let delayedCount = 0;
    const url = new URL(endpoint);
    url.searchParams.set(parameter, variant.finalValue);
    const fullUrl = url.toString();

    for (let i = 0; i < attempts; i++) {
      try {
        const start = Date.now();
        await this.httpClient.request({
          method: method as HttpMethod,
          url: fullUrl,
        });
        const elapsed = Date.now() - start;

        if (elapsed >= thresholdMs) {
          delayedCount++;
        }
      } catch {
        logger.warn({ findingId, attempt: i }, 'Timing confirmation replay failed');
      }
    }

    const ratio = delayedCount / attempts;
    return {
      findingId,
      verified: ratio >= 0.5,
      replayCount: attempts,
      consistentResponse: ratio >= 1.0,
      confidence: ratio >= 1.0 ? 'CONFIRMED' : ratio >= 0.5 ? 'HIGH' : 'LOW',
      strategy: 'TIMING_CONFIRMATION',
    };
  }
}
