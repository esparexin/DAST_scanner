import { describe, it, expect, vi } from 'vitest';
import { SoapTester } from '../soap-tester.js';

describe('SoapTester', () => {
  const sampleWsdl = `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:portType name="PaymentService">
    <wsdl:operation name="ProcessPayment"/>
    <wsdl:operation name="RefundPayment"/>
  </wsdl:portType>
</wsdl:definitions>`;

  it('discovers WSDL contract and extracts operation names', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'text/xml; charset=utf-8' },
        body: sampleWsdl,
      }),
    };

    const tester = new SoapTester(mockClient as any);
    const result = await tester.inspectWsdl('https://api.example.com/payments');
    expect(result.wsdlDiscovered).toBe(true);
    expect(result.operations).toContain('ProcessPayment');
    expect(result.operations).toContain('RefundPayment');
    expect(result.securityIssues.some((i) => i.includes('Publicly accessible WSDL'))).toBe(true);
  });

  it('builds well-formed safe SOAP probe envelope', () => {
    const tester = new SoapTester({} as any);
    const env = tester.buildSafeProbeEnvelope('GetStatus');
    expect(env).toContain('<GetStatus xmlns="http://tempuri.org/"/>');
    expect(env).toContain('soap:Envelope');
  });
});
