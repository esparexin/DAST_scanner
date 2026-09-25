import type { TargetReflectionContext } from '../types/payload-definition.js';
import type { SecureHttpClient } from '@securityscan/http-client';
import { HttpMethod } from '@securityscan/contracts';
import { CanaryGenerator } from '../canary/canary-generator.js';

export interface ReflectionAnalysisResult {
  reflected: boolean;
  context: TargetReflectionContext;
  snippet?: string;
  isHtmlEscaped: boolean;
}

/**
 * Probes target endpoints with neutral, non-special tokens to detect reflection context
 * (HTML body vs. attribute vs. script block vs. none) BEFORE sending active payloads.
 */
export class ReflectionContextAnalyzer {
  private readonly httpClient: SecureHttpClient;

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  async analyzeReflection(
    targetUrl: string,
    paramName: string,
    method: HttpMethod = HttpMethod.GET,
  ): Promise<ReflectionAnalysisResult> {
    const canary = CanaryGenerator.generate('probe', 'ALPHANUMERIC');
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set(paramName, canary.token);

    try {
      const res = await this.httpClient.request({
        method,
        url: testUrl.toString(),
      });

      const contentType = (res.headers['content-type'] ?? '').toLowerCase();
      if (!contentType.includes('text/html')) {
        return { reflected: false, context: 'ANY', isHtmlEscaped: false };
      }

      const body = res.body;
      const tokenIndex = body.indexOf(canary.token);
      if (tokenIndex === -1) {
        // Token was not reflected anywhere
        return { reflected: false, context: 'ANY', isHtmlEscaped: false };
      }

      // Extract surrounding window of 80 characters before and after
      const start = Math.max(0, tokenIndex - 80);
      const end = Math.min(body.length, tokenIndex + canary.token.length + 80);
      const surrounding = body.slice(start, end);

      // Inspect if inside <script> tag
      const precedingText = body.slice(0, tokenIndex);
      const lastScriptOpen = precedingText.lastIndexOf('<script');
      const lastScriptClose = precedingText.lastIndexOf('</script>');
      if (lastScriptOpen !== -1 && lastScriptOpen > lastScriptClose) {
        return {
          reflected: true,
          context: 'JAVASCRIPT_BLOCK',
          snippet: surrounding,
          isHtmlEscaped: false,
        };
      }

      // Inspect if inside tag attribute: e.g. <input value="CANARY" or <div data-id='CANARY'
      const lastTagOpen = precedingText.lastIndexOf('<');
      const lastTagClose = precedingText.lastIndexOf('>');
      if (lastTagOpen !== -1 && lastTagOpen > lastTagClose) {
        return {
          reflected: true,
          context: 'HTML_ATTRIBUTE',
          snippet: surrounding,
          isHtmlEscaped: false,
        };
      }

      // Default: Reflected inside normal HTML body markup
      return {
        reflected: true,
        context: 'HTML_BODY',
        snippet: surrounding,
        isHtmlEscaped: false,
      };
    } catch {
      return { reflected: false, context: 'ANY', isHtmlEscaped: false };
    }
  }
}
