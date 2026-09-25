import type { SecureHttpClient } from '@securityscan/http-client';
import { AuthApplicator } from '@securityscan/authentication';
import type { AuthType, IAuthConfiguration, HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('authorization-tester');

export interface TestIdentity {
  name: string;
  role: string;
  authType: AuthType;
  authConfig: IAuthConfiguration;
  expectedAccess: boolean;
}

export interface AuthzTestResult {
  endpoint: string;
  method: string;
  identity: string;
  role: string;
  expectedAccess: boolean;
  actualStatusCode: number;
  actualAccess: boolean;
  isViolation: boolean;
}

/**
 * Tests authorization by sending the same request with different identities
 * and comparing access results.
 */
export class AuthorizationTester {
  private readonly httpClient: SecureHttpClient;
  private readonly authApplicator = new AuthApplicator();

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  async testEndpoint(
    url: string,
    method: HttpMethod,
    identities: TestIdentity[],
  ): Promise<AuthzTestResult[]> {
    const results: AuthzTestResult[] = [];

    for (const identity of identities) {
      try {
        const headers = this.authApplicator.apply(identity.authType, identity.authConfig, {});
        const response = await this.httpClient.request({ method, url, headers });
        const actualAccess = this.isSuccessfulAccess(response.statusCode);
        const isViolation = actualAccess && !identity.expectedAccess;

        results.push({
          endpoint: url,
          method,
          identity: identity.name,
          role: identity.role,
          expectedAccess: identity.expectedAccess,
          actualStatusCode: response.statusCode,
          actualAccess,
          isViolation,
        });

        if (isViolation) {
          logger.info(
            { endpoint: url, identity: identity.name, statusCode: response.statusCode },
            'Authorization violation detected',
          );
        }
      } catch (error) {
        logger.debug({ endpoint: url, identity: identity.name, error: (error as Error).message }, 'Auth test request failed');
      }
    }

    return results;
  }

  private isSuccessfulAccess(statusCode: number): boolean {
    return statusCode >= 200 && statusCode < 400;
  }
}
