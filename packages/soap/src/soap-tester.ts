import type { SecureHttpClient } from '@securityscan/http-client';
import { HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('soap-tester');

export interface SoapAnalysisResult {
  endpointUrl: string;
  wsdlDiscovered: boolean;
  operations: string[];
  securityIssues: string[];
}

export class SoapTester {
  private readonly httpClient: SecureHttpClient;

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Discover and parse WSDL service definitions
   */
  async inspectWsdl(serviceUrl: string): Promise<SoapAnalysisResult> {
    const wsdlUrl = serviceUrl.includes('?wsdl') ? serviceUrl : `${serviceUrl}?wsdl`;
    const issues: string[] = [];
    const operations: string[] = [];
    let wsdlDiscovered = false;

    try {
      const res = await this.httpClient.request({
        method: HttpMethod.GET,
        url: wsdlUrl,
      });

      if (res.statusCode === 200 && res.body.includes('<wsdl:definitions') || res.body.includes('<definitions')) {
        wsdlDiscovered = true;
        issues.push('Publicly accessible WSDL definition discloses entire SOAP service contract');

        // Extract operations
        const opRegex = /<wsdl:operation[^>]*name=["']([^"']+)["']/gi;
        let match;
        while ((match = opRegex.exec(res.body)) !== null) {
          if (match[1] && !operations.includes(match[1])) {
            operations.push(match[1]);
          }
        }
      }
    } catch (err) {
      logger.debug({ serviceUrl, error: (err as Error).message }, 'SOAP WSDL inspect non-fatal error');
    }

    return {
      endpointUrl: serviceUrl,
      wsdlDiscovered,
      operations,
      securityIssues: issues,
    };
  }

  /**
   * Build safe probe envelope for checking XML schema parsing without external entity loading
   */
  buildSafeProbeEnvelope(operationName: string): string {
    return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <${operationName} xmlns="http://tempuri.org/"/>
  </soap:Body>
</soap:Envelope>`;
  }
}
