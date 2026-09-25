import type { IBrowserDriver, SpaRouteDiscovery } from './types.js';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('browser-engine');

/**
 * Headless Browser Discovery Engine for Modern SPAs.
 * Extracts dynamically rendered routes, intercepted API network calls, and DOM sinks.
 */
export class BrowserEngine {
  private readonly driver: IBrowserDriver;

  constructor(driver: IBrowserDriver) {
    this.driver = driver;
  }

  async analyzeSpa(targetUrl: string, timeoutMs: number = 15000): Promise<SpaRouteDiscovery> {
    logger.info({ targetUrl }, 'Initiating SPA browser dynamic extraction');
    try {
      const result = await this.driver.navigateAndExtract(targetUrl, timeoutMs);
      logger.info(
        {
          targetUrl,
          linksDiscovered: result.discoveredLinks.length,
          apiCallsIntercepted: result.xhrRequestsIntercepted.length,
        },
        'SPA browser extraction completed',
      );
      return result;
    } catch (error) {
      logger.warn({ targetUrl, error: (error as Error).message }, 'Browser dynamic extraction failed');
      return {
        url: targetUrl,
        pageTitle: '',
        discoveredLinks: [],
        discoveredForms: [],
        xhrRequestsIntercepted: [],
        domXssSinksObserved: [],
      };
    }
  }
}
