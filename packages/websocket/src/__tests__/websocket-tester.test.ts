import { describe, it, expect, vi } from 'vitest';
import { WebSocketTester } from '../websocket-tester.js';

describe('WebSocketTester', () => {
  it('flags unencrypted ws:// protocol', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({ statusCode: 404, headers: {} }),
    };
    const tester = new WebSocketTester(mockClient as any);
    const result = await tester.testHandshake('ws://example.com/chat');
    expect(result.supportsUnencryptedWs).toBe(true);
    expect(result.securityIssues.some((i) => i.includes('unencrypted ws://'))).toBe(true);
  });

  it('detects Cross-Site WebSocket Hijacking when arbitrary Origin is accepted', async () => {
    const mockClient = {
      request: vi.fn().mockResolvedValue({
        statusCode: 101,
        headers: { upgrade: 'websocket', connection: 'Upgrade' },
      }),
    };
    const tester = new WebSocketTester(mockClient as any);
    const result = await tester.testHandshake('wss://example.com/chat');
    expect(result.isWebSocketEndpoint).toBe(true);
    expect(result.originEnforced).toBe(false);
    expect(result.securityIssues.some((i) => i.includes('Cross-Site WebSocket Hijacking'))).toBe(true);
  });
});
