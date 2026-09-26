import { ScopeValidationResult, DEFAULT_USER_AGENT, MAX_REDIRECT_CHAIN } from '@securityscan/contracts';
import type { IHttpRequest, IHttpResponse, IHttpClientConfig } from '@securityscan/contracts';
import type { ScopeValidator } from '@securityscan/scope';
import { ScopeError, createLogger } from '@securityscan/shared';
import { RateLimiter } from './rate-limiter.js';

const logger = createLogger('http-client');

/**
 * Centralized HTTP client with mandatory scope enforcement.
 * ALL outbound requests from the scanner MUST go through this client.
 * Individual checks must NEVER bypass this layer.
 */
export class SecureHttpClient {
  private readonly scopeValidator: ScopeValidator;
  private readonly rateLimiter: RateLimiter;
  private readonly config: Required<IHttpClientConfig>;
  private aborted = false;

  constructor(
    scopeValidator: ScopeValidator,
    rateLimiter?: RateLimiter,
    config?: IHttpClientConfig,
  ) {
    this.scopeValidator = scopeValidator;
    this.rateLimiter = rateLimiter ?? new RateLimiter(1000);
    this.config = {
      baseHeaders: config?.baseHeaders ?? {},
      timeout: config?.timeout ?? 30000,
      followRedirects: config?.followRedirects ?? false, // We handle redirects manually for scope checking
      maxRedirects: config?.maxRedirects ?? MAX_REDIRECT_CHAIN,
      maxResponseSize: config?.maxResponseSize ?? 10 * 1024 * 1024,
      userAgent: config?.userAgent ?? DEFAULT_USER_AGENT,
    };
  }

  async request(req: IHttpRequest): Promise<IHttpResponse> {
    if (this.aborted) {
      throw new ScopeError('HTTP client has been aborted');
    }

    // MANDATORY: Validate URL against scope
    const validation = this.scopeValidator.validate(req.url);
    if (validation.result !== ScopeValidationResult.ALLOWED) {
      throw new ScopeError(validation.reason ?? `Request blocked: ${validation.result}`);
    }

    // Rate limit
    await this.rateLimiter.acquire();

    // Record the request
    this.scopeValidator.recordRequest();

    const startTime = Date.now();
    const headers: Record<string, string> = {
      'User-Agent': this.config.userAgent,
      ...this.config.baseHeaders,
      ...(req.headers ?? {}),
    };

    const timeout = req.timeout ?? this.config.timeout;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const fetchResponse = await fetch(req.url, {
        method: req.method,
        headers,
        body: req.body ? (typeof req.body === 'string' ? req.body : req.body) : undefined,
        signal: controller.signal,
        redirect: 'manual', // We handle redirects manually for scope validation
      });

      clearTimeout(timeoutId);

      // Handle redirects with scope validation
      if (this.isRedirect(fetchResponse.status) && (req.followRedirects ?? this.config.followRedirects)) {
        return this.followRedirect(fetchResponse, req, 0);
      }

      const body = await this.readBody(fetchResponse);
      const responseTime = Date.now() - startTime;

      const responseHeaders: Record<string, string> = {};
      fetchResponse.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      return {
        statusCode: fetchResponse.status,
        headers: responseHeaders,
        body,
        responseTime,
        url: req.url,
        size: body.length,
      };
    } catch (error) {
      if (error instanceof ScopeError) throw error;
      const message = error instanceof Error ? error.message : 'Unknown error';
      logger.debug({ url: req.url, error: message }, 'HTTP request failed');
      throw new Error(`HTTP request to ${req.url} failed: ${message}`);
    }
  }

  private async followRedirect(
    response: Response,
    originalReq: IHttpRequest,
    depth: number,
  ): Promise<IHttpResponse> {
    if (depth >= this.config.maxRedirects) {
      throw new Error(`Maximum redirect depth (${this.config.maxRedirects}) exceeded`);
    }

    const location = response.headers.get('location');
    if (!location) {
      throw new Error('Redirect response missing Location header');
    }

    const redirectUrl = new URL(location, originalReq.url).toString();

    // MANDATORY: Validate redirect target against scope
    const validation = this.scopeValidator.validate(redirectUrl);
    if (validation.result !== ScopeValidationResult.ALLOWED) {
      // Return the redirect response instead of following
      const body = await this.readBody(response);
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((v, k) => { responseHeaders[k] = v; });
      return {
        statusCode: response.status,
        headers: responseHeaders,
        body,
        responseTime: 0,
        url: originalReq.url,
        redirectChain: [redirectUrl],
        size: body.length,
      };
    }

    return this.request({ ...originalReq, url: redirectUrl });
  }

  private isRedirect(status: number): boolean {
    return [301, 302, 303, 307, 308].includes(status);
  }

  private async readBody(response: Response): Promise<string> {
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > this.config.maxResponseSize) {
      return '[Response too large - truncated]';
    }
    try {
      const text = await response.text();
      if (text.length > this.config.maxResponseSize) {
        return text.slice(0, this.config.maxResponseSize) + '\n[truncated]';
      }
      return text;
    } catch {
      return '[Failed to read response body]';
    }
  }

  abort(): void {
    this.aborted = true;
    this.scopeValidator.cancel();
  }
}
