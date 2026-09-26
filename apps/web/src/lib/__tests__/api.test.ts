import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  fetchApi,
  getAuthToken,
  setAuthToken,
  clearAuthToken,
  ApiError,
  authApi,
  scansApi,
  AUTH_TOKEN_KEY,
} from '../api.js';

describe('Web API Client & Authentication Layer', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    if (typeof localStorage !== 'undefined') {
      localStorage.clear();
    }
  });

  it('manages auth tokens in localStorage correctly', () => {
    expect(getAuthToken()).toBeNull();

    setAuthToken('test-jwt-token-123');
    expect(getAuthToken()).toBe('test-jwt-token-123');
    if (typeof localStorage !== 'undefined') {
      expect(localStorage.getItem(AUTH_TOKEN_KEY)).toBe('test-jwt-token-123');
    }

    clearAuthToken();
    expect(getAuthToken()).toBeNull();
    if (typeof localStorage !== 'undefined') {
      expect(localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
    }
  });

  it('automatically attaches Authorization header when token is present', async () => {
    setAuthToken('my-secret-token');

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ data: { success: true } }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await fetchApi<{ success: boolean }>('/api/scans');
    expect(result).toEqual({ success: true });

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/scans'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          Authorization: 'Bearer my-secret-token',
        }),
      }),
    );
  });

  it('clears auth token and throws structured ApiError on 401 response', async () => {
    setAuthToken('expired-token');

    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ error: { code: 'UNAUTHORIZED', message: 'Token expired' } }),
    });
    vi.stubGlobal('fetch', mockFetch);

    await expect(fetchApi('/api/scans')).rejects.toThrow(ApiError);
    expect(getAuthToken()).toBeNull(); // Token cleared on 401
  });

  it('maps 403 Forbidden to a descriptive user error', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      json: async () => ({
        error: { code: 'SCOPE_VIOLATION', message: 'Target is not authorized' },
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    try {
      await fetchApi('/api/scans');
      expect.fail('Should have thrown');
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ApiError);
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.code).toBe('SCOPE_VIOLATION');
      expect(apiErr.message).toContain('Access denied');
    }
  });

  it('appends token parameter to SSE events URL when authenticated', () => {
    setAuthToken('token-abc');
    const url = scansApi.getEventsUrl('scan-99');
    expect(url).toContain('/api/scans/scan-99/events?token=token-abc');

    clearAuthToken();
    const unauthUrl = scansApi.getEventsUrl('scan-99');
    expect(unauthUrl).toBe('http://localhost:3001/api/scans/scan-99/events');
  });

  it('logs out and clears session via authApi.logout()', () => {
    setAuthToken('active-token');
    authApi.logout();
    expect(getAuthToken()).toBeNull();
  });
});
