import type { SecureHttpClient } from '@securityscan/http-client';
import { HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('grpc-tester');

export interface GrpcServiceAnalysis {
  host: string;
  isGrpcWebEndpoint: boolean;
  reflectionExposed: boolean;
  securityIssues: string[];
}

export class GrpcTester {
  private readonly httpClient: SecureHttpClient;

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Analyze gRPC-Web endpoint headers and reflection exposure
   */
  async testEndpoint(url: string): Promise<GrpcServiceAnalysis> {
    const issues: string[] = [];
    let isGrpcWeb = false;
    let reflectionExposed = false;

    try {
      // Test gRPC-web content type probing
      const res = await this.httpClient.request({
        method: HttpMethod.POST,
        url,
        headers: {
          'content-type': 'application/grpc-web+proto',
          'x-grpc-web': '1',
        },
        body: Buffer.from([0, 0, 0, 0, 0]), // gRPC framing: uncompressed 0-length payload
      });

      const contentType = res.headers['content-type'] ?? '';
      const grpcStatus = res.headers['grpc-status'];

      if (contentType.includes('grpc') || grpcStatus !== undefined) {
        isGrpcWeb = true;
      }

      // Test reflection endpoint
      const reflectionUrl = `${url.replace(/\/[^/]+$/, '')}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`;
      const reflRes = await this.httpClient.request({
        method: HttpMethod.POST,
        url: reflectionUrl,
        headers: { 'content-type': 'application/grpc-web+proto' },
        body: Buffer.from([0, 0, 0, 0, 0]),
      });

      if (reflRes.statusCode === 200 || reflRes.headers['grpc-status'] === '0') {
        reflectionExposed = true;
        issues.push('gRPC Server Reflection is enabled in production, disclosing entire service and message schema');
      }
    } catch (err) {
      logger.debug({ url, error: (err as Error).message }, 'gRPC probe error');
    }

    return {
      host: url,
      isGrpcWebEndpoint: isGrpcWeb,
      reflectionExposed,
      securityIssues: issues,
    };
  }
}
