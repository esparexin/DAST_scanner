import type {
  IRedactedHttpRequest,
  IRedactedHttpResponse,
  IProofOfConcept,
  IReproductionStep,
} from '@securityscan/contracts';
import { redactSensitiveHeaders, redactSensitiveBody } from '@securityscan/shared';

export interface PocInput {
  findingId: string;
  title: string;
  description: string;
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  response: { statusCode: number; headers: Record<string, string>; body?: string; responseTime: number };
  expectedBehavior: string;
  observedBehavior: string;
  remediation: string;
  preconditions?: string[];
  additionalSteps?: Array<{ description: string }>;
}

/**
 * Generates safe, reproducible PoCs.
 * Detection -> Verification -> Proof -> (no automatic exploitation)
 */
export class PocGenerator {
  generate(input: PocInput): Omit<IProofOfConcept, 'id' | 'createdAt' | 'evidence'> {
    const request: IRedactedHttpRequest = {
      method: input.request.method,
      url: input.request.url,
      headers: redactSensitiveHeaders(input.request.headers),
      body: input.request.body ? redactSensitiveBody(input.request.body) : undefined,
    };

    const response: IRedactedHttpResponse = {
      statusCode: input.response.statusCode,
      headers: redactSensitiveHeaders(input.response.headers),
      body: input.response.body ? redactSensitiveBody(input.response.body).slice(0, 5000) : undefined,
      responseTime: input.response.responseTime,
    };

    const steps: IReproductionStep[] = [
      {
        order: 1,
        description: `Send ${input.request.method} request to ${input.request.url}`,
        request,
        response,
      },
    ];

    if (input.additionalSteps) {
      for (let i = 0; i < input.additionalSteps.length; i++) {
        steps.push({
          order: i + 2,
          description: input.additionalSteps[i]!.description,
        });
      }
    }

    return {
      findingId: input.findingId,
      summary: `${input.title}: ${input.description}`,
      preconditions: input.preconditions ?? ['Authorized access to the target application'],
      steps,
      request,
      response,
      expectedBehavior: input.expectedBehavior,
      observedBehavior: input.observedBehavior,
      remediation: input.remediation,
    };
  }
}
