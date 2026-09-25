import type { SecureHttpClient } from '@securityscan/http-client';
import { HttpMethod } from '@securityscan/contracts';
import { createLogger } from '@securityscan/shared';
import { LinkExtractor } from './link-extractor.js';

const logger = createLogger('crawler');

export interface CrawlResult {
  url: string;
  method: HttpMethod;
  statusCode: number;
  contentType: string;
  links: string[];
  forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>;
  headers: Record<string, string>;
}

export class Crawler {
  private readonly httpClient: SecureHttpClient;
  private readonly linkExtractor = new LinkExtractor();
  private visited: Set<string> = new Set();
  private readonly maxDepth: number;

  constructor(httpClient: SecureHttpClient, maxDepth: number = 5) {
    this.httpClient = httpClient;
    this.maxDepth = maxDepth;
  }

  async crawl(startUrl: string, depth: number = 0): Promise<CrawlResult[]> {
    if (depth > this.maxDepth || this.visited.has(startUrl)) {
      return [];
    }
    this.visited.add(startUrl);

    const results: CrawlResult[] = [];
    try {
      const response = await this.httpClient.request({
        method: HttpMethod.GET,
        url: startUrl,
      });

      const contentType = response.headers['content-type'] ?? '';
      const links = contentType.includes('text/html')
        ? this.linkExtractor.extractLinks(response.body, startUrl)
        : [];
      const forms = contentType.includes('text/html')
        ? this.linkExtractor.extractForms(response.body, startUrl)
        : [];

      // Also extract from JS
      if (contentType.includes('javascript')) {
        links.push(...this.linkExtractor.extractJsUrls(response.body, startUrl));
      }

      results.push({
        url: startUrl,
        method: HttpMethod.GET,
        statusCode: response.statusCode,
        contentType,
        links,
        forms,
        headers: response.headers,
      });

      logger.debug({ url: startUrl, links: links.length, depth }, 'Page crawled');

      // Recursively crawl discovered links
      for (const link of links) {
        if (!this.visited.has(link)) {
          try {
            const childResults = await this.crawl(link, depth + 1);
            results.push(...childResults);
          } catch {
            // Scope or network errors on child links are non-fatal
          }
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown';
      logger.debug({ url: startUrl, error: message }, 'Crawl failed for URL');
    }

    return results;
  }

  getVisitedUrls(): string[] {
    return Array.from(this.visited);
  }

  reset(): void {
    this.visited.clear();
  }
}
