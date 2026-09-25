import type { SecureHttpClient } from '@securityscan/http-client';
import { HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('websocket-tester');

export interface WebSocketHandshakeResult {
  url: string;
  isWebSocketEndpoint: boolean;
  originEnforced: boolean;
  supportsUnencryptedWs: boolean;
  securityIssues: string[];
}

export class WebSocketTester {
  private readonly httpClient: SecureHttpClient;

  constructor(httpClient: SecureHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Test WebSocket handshake security (Origin validation & unencrypted ws:// usage)
   */
  async testHandshake(wsUrl: string): Promise<WebSocketHandshakeResult> {
    const httpUrl = wsUrl.replace(/^ws(s?):\/\//i, 'http$1://');
    const issues: string[] = [];
    let isWs = false;
    let originEnforced = true;

    if (wsUrl.startsWith('ws://')) {
      issues.push('WebSocket uses unencrypted ws:// protocol rather than secure wss:// (cleartext transmission)');
    }

    try {
      // Test standard upgrade handshake
      const handshakeRes = await this.httpClient.request({
        method: HttpMethod.GET,
        url: httpUrl,
        headers: {
          Upgrade: 'websocket',
          Connection: 'Upgrade',
          'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
          'Sec-WebSocket-Version': '13',
        },
      });

      if (handshakeRes.statusCode === 101 || (handshakeRes.headers['upgrade'] ?? '').toLowerCase() === 'websocket') {
        isWs = true;
      }

      // Test cross-site origin handling (CSWSH check)
      const evilOriginRes = await this.httpClient.request({
        method: HttpMethod.GET,
        url: httpUrl,
        headers: {
          Upgrade: 'websocket',
          Connection: 'Upgrade',
          'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
          'Sec-WebSocket-Version': '13',
          Origin: 'https://attacker-origin.corp',
        },
      });

      if (evilOriginRes.statusCode === 101) {
        originEnforced = false;
        issues.push('Cross-Site WebSocket Hijacking (CSWSH): Endpoint accepts arbitrary Origin headers during handshake');
      }
    } catch (err) {
      logger.debug({ wsUrl, error: (err as Error).message }, 'WebSocket handshake test non-fatal failure');
    }

    return {
      url: wsUrl,
      isWebSocketEndpoint: isWs,
      originEnforced,
      supportsUnencryptedWs: wsUrl.startsWith('ws://'),
      securityIssues: issues,
    };
  }
}
