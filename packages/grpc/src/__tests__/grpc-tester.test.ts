import { describe, it, expect, vi } from 'vitest';
import { GrpcTester } from '../grpc-tester.js';

describe('GrpcTester', () => {
  it('identifies gRPC-Web endpoint from response headers', async () => {
    const mockClient = {
      request: vi.fn().mockImplementation((req) => {
        if (req.url.includes('ServerReflection')) {
          return Promise.resolve({ statusCode: 404, headers: {} });
        }
        return Promise.resolve({
          statusCode: 200,
          headers: { 'content-type': 'application/grpc-web+proto', 'grpc-status': '12' },
        });
      }),
    };

    const tester = new GrpcTester(mockClient as any);
    const result = await tester.testEndpoint('https://api.example.com/greet.Greeter/SayHello');
    expect(result.isGrpcWebEndpoint).toBe(true);
    expect(result.reflectionExposed).toBe(false);
  });

  it('detects exposed server reflection service', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 200,
        headers: { 'content-type': 'application/grpc-web+proto', 'grpc-status': '0' },
      }),
    };

    const tester = new GrpcTester(mockClient as any);
    const result = await tester.testEndpoint('https://api.example.com/service');
    expect(result.reflectionExposed).toBe(true);
    expect(result.securityIssues.some((i) => i.includes('Server Reflection'))).toBe(true);
  });
});
