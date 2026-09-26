import { ScopeValidationResult } from '@securityscan/contracts';
import type { IScopeConfig, IScopeValidation } from '@securityscan/contracts';
import { ScopeError } from '@securityscan/shared';
import { isPrivateIp } from './private-ip.js';

/**
 * Centralized scope validator. Every outbound request MUST pass through this.
 * 
 * NO AUTHORIZATION + NO VALID SCOPE = NO REQUEST
 */
export class ScopeValidator {
  private readonly config: IScopeConfig;
  private requestCount: number = 0;
  private readonly startTime: number;
  private cancelled: boolean = false;

  constructor(config: IScopeConfig | string[]) {
    if (Array.isArray(config)) {
      const allowedHosts: string[] = [];
      const allowedPaths: string[] = [];
      for (const item of config) {
        try {
          const urlStr = item.includes('://') ? item : `http://${item}`;
          const url = new URL(urlStr.replace(/\/\*.*$/, ''));
          if (url.hostname && !allowedHosts.includes(url.hostname)) {
            allowedHosts.push(url.hostname);
          }
          if (url.pathname && url.pathname !== '/' && !allowedPaths.includes(url.pathname)) {
            allowedPaths.push(url.pathname);
          }
        } catch {
          if (!allowedHosts.includes(item)) {
            allowedHosts.push(item);
          }
        }
      }
      this.config = {
        scanId: 'lab-scan',
        targetId: 'lab-target',
        projectId: 'lab-project',
        authorized: true,
        allowedHosts: allowedHosts.length > 0 ? allowedHosts : ['*'],
        excludedHosts: [],
        allowedPaths,
        excludedPaths: [],
        maxRequestsPerSecond: 10000,
        maxConcurrency: 100,
        maxRequests: 100000,
        maxCrawlDepth: 10,
        maxResponseSize: 10 * 1024 * 1024,
        maxScanDuration: 3600,
        timeoutPerRequest: 30,
      };
      this.startTime = Date.now();
      return;
    }

    if (!config.authorized) {
      throw new ScopeError('Target is not authorized. Cannot create scope validator.');
    }
    if (config.allowedHosts.length === 0) {
      throw new ScopeError('No allowed hosts defined. Cannot create scope validator.');
    }
    this.config = config;
    this.startTime = Date.now();
  }

  /**
   * Validate whether a URL is within scope.
   * Returns ALLOWED or a specific rejection reason.
   */
  validate(url: string): IScopeValidation {
    // Check cancellation first
    if (this.cancelled) {
      return {
        result: ScopeValidationResult.SCAN_CANCELLED,
        url,
        reason: 'Scan has been cancelled',
      };
    }

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return {
        result: ScopeValidationResult.BLOCKED_HOST,
        url,
        reason: `Invalid URL: ${url}`,
      };
    }

    const hostname = parsed.hostname;
    const pathname = parsed.pathname;

    // 1. Check if host is in allowed list
    if (!this.isHostAllowed(hostname)) {
      return {
        result: ScopeValidationResult.BLOCKED_HOST,
        url,
        reason: `Host '${hostname}' is not in the allowed hosts list`,
      };
    }

    // 2. Check if host is in excluded list
    if (this.isHostExcluded(hostname)) {
      return {
        result: ScopeValidationResult.BLOCKED_EXCLUDED,
        url,
        reason: `Host '${hostname}' is in the excluded hosts list`,
      };
    }

    // 3. Check allowed paths (if specified)
    if (this.config.allowedPaths.length > 0 && !this.isPathAllowed(pathname)) {
      return {
        result: ScopeValidationResult.BLOCKED_PATH,
        url,
        reason: `Path '${pathname}' is not in the allowed paths list`,
      };
    }

    // 4. Check excluded paths
    if (this.isPathExcluded(pathname)) {
      return {
        result: ScopeValidationResult.BLOCKED_PATH,
        url,
        reason: `Path '${pathname}' is in the excluded paths list`,
      };
    }

    // 5. Check request count limit
    if (this.requestCount >= this.config.maxRequests) {
      return {
        result: ScopeValidationResult.REQUEST_LIMIT_EXCEEDED,
        url,
        reason: `Request limit of ${this.config.maxRequests} exceeded`,
      };
    }

    // 6. Check scan duration
    const elapsed = (Date.now() - this.startTime) / 1000;
    if (elapsed >= this.config.maxScanDuration) {
      return {
        result: ScopeValidationResult.DURATION_EXCEEDED,
        url,
        reason: `Scan duration limit of ${this.config.maxScanDuration}s exceeded`,
      };
    }

    return {
      result: ScopeValidationResult.ALLOWED,
      url,
    };
  }

  /**
   * Validate a URL and throw if not allowed.
   */
  validateOrThrow(url: string): void {
    const result = this.validate(url);
    if (result.result !== ScopeValidationResult.ALLOWED) {
      throw new ScopeError(result.reason ?? `Request to ${url} blocked: ${result.result}`);
    }
  }

  /**
   * Validate that a resolved IP address is not private/internal.
   */
  validateIp(ip: string, url: string): IScopeValidation {
    if (isPrivateIp(ip)) {
      return {
        result: ScopeValidationResult.BLOCKED_PRIVATE_IP,
        url,
        reason: `Resolved IP '${ip}' is a private/internal address`,
      };
    }
    return {
      result: ScopeValidationResult.ALLOWED,
      url,
    };
  }

  /**
   * Record that a request was made (for counting).
   */
  recordRequest(): void {
    this.requestCount++;
  }

  /**
   * Cancel this scope (all future validations will fail).
   */
  cancel(): void {
    this.cancelled = true;
  }

  /**
   * Get current statistics.
   */
  getStats(): { requestCount: number; elapsedSeconds: number; cancelled: boolean } {
    return {
      requestCount: this.requestCount,
      elapsedSeconds: (Date.now() - this.startTime) / 1000,
      cancelled: this.cancelled,
    };
  }

  private isHostAllowed(hostname: string): boolean {
    return this.config.allowedHosts.some((allowed) => {
      if (allowed === '*') return true;
      if (allowed.startsWith('*.')) {
        // Wildcard subdomain match
        const domain = allowed.slice(2);
        return hostname === domain || hostname.endsWith('.' + domain);
      }
      return hostname === allowed;
    });
  }

  private isHostExcluded(hostname: string): boolean {
    return this.config.excludedHosts.some((excluded) => {
      if (excluded.startsWith('*.')) {
        const domain = excluded.slice(2);
        return hostname === domain || hostname.endsWith('.' + domain);
      }
      return hostname === excluded;
    });
  }

  private isPathAllowed(pathname: string): boolean {
    return this.config.allowedPaths.some((allowed) => {
      return pathname === allowed || pathname.startsWith(allowed);
    });
  }

  private isPathExcluded(pathname: string): boolean {
    return this.config.excludedPaths.some((excluded) => {
      return pathname === excluded || pathname.startsWith(excluded);
    });
  }
}
