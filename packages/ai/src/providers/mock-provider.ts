import type { IAIProvider, AIModelMessage, AICompletionOptions } from '../types.js';

export class MockAIProvider implements IAIProvider {
  public readonly name = 'mock';
  private mockResponse?: string;

  constructor(mockResponse?: string) {
    this.mockResponse = mockResponse;
  }

  setMockResponse(resp: string): void {
    this.mockResponse = resp;
  }

  async generateCompletion(_messages: AIModelMessage[], _options?: AICompletionOptions): Promise<string> {
    if (this.mockResponse) return this.mockResponse;

    return JSON.stringify({
      rootCauseSummary: 'The application reflects user input or configuration without proper validation.',
      technicalImpact: 'Unauthorized state tampering or disclosure of protected parameters.',
      falsePositiveLikelihood: 'LOW',
      falsePositiveRationale: 'Evidence clearly demonstrates non-conformant response headers and behavioral mismatch.',
      suggestedVerificationStrategy: 'Replay baseline request and confirm persistence of differential response across varying payloads.',
      tailoredRemediation: 'Apply server-side validation and configure strict security headers.',
      remediationCodeSample: 'app.use(helmet());',
    });
  }
}
