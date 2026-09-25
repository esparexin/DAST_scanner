/**
 * Extract links and resources from HTML content.
 */
export class LinkExtractor {
  extractLinks(html: string, baseUrl: string): string[] {
    const urls: Set<string> = new Set();

    // Extract href attributes
    const hrefRegex = /href=["']([^"']+)["']/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
      const resolved = this.resolveUrl(match[1]!, baseUrl);
      if (resolved) urls.add(resolved);
    }

    // Extract src attributes
    const srcRegex = /src=["']([^"']+)["']/gi;
    while ((match = srcRegex.exec(html)) !== null) {
      const resolved = this.resolveUrl(match[1]!, baseUrl);
      if (resolved) urls.add(resolved);
    }

    // Extract action attributes (forms)
    const actionRegex = /action=["']([^"']+)["']/gi;
    while ((match = actionRegex.exec(html)) !== null) {
      const resolved = this.resolveUrl(match[1]!, baseUrl);
      if (resolved) urls.add(resolved);
    }

    return Array.from(urls);
  }

  extractForms(html: string, baseUrl: string): Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }> {
    const forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }> = [];
    const formRegex = /<form[^>]*>(.*?)<\/form>/gis;
    let formMatch;
    while ((formMatch = formRegex.exec(html)) !== null) {
      const formTag = formMatch[0]!;
      const actionMatch = /action=["']([^"']*)["']/i.exec(formTag);
      const methodMatch = /method=["']([^"']*)["']/i.exec(formTag);
      const action = this.resolveUrl(actionMatch?.[1] ?? '', baseUrl) ?? baseUrl;
      const method = (methodMatch?.[1] ?? 'GET').toUpperCase();

      const inputs: Array<{ name: string; type: string }> = [];
      const inputRegex = /<input[^>]*>/gi;
      let inputMatch;
      while ((inputMatch = inputRegex.exec(formMatch[1] ?? '')) !== null) {
        const nameMatch = /name=["']([^"']*)["']/i.exec(inputMatch[0]!);
        const typeMatch = /type=["']([^"']*)["']/i.exec(inputMatch[0]!);
        if (nameMatch?.[1]) {
          inputs.push({ name: nameMatch[1], type: typeMatch?.[1] ?? 'text' });
        }
      }

      forms.push({ action, method, inputs });
    }
    return forms;
  }

  extractJsUrls(js: string, baseUrl: string): string[] {
    const urls: Set<string> = new Set();
    const patterns = [
      /["'`](\/api\/[^"'`\s]+)["'`]/g,
      /["'`](\/v[0-9]+\/[^"'`\s]+)["'`]/g,
      /fetch\(["'`]([^"'`]+)["'`]/g,
      /\.(?:get|post|put|patch|delete)\(["'`]([^"'`]+)["'`]/g,
    ];
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(js)) !== null) {
        const resolved = this.resolveUrl(match[1]!, baseUrl);
        if (resolved) urls.add(resolved);
      }
    }
    return Array.from(urls);
  }

  private resolveUrl(url: string, baseUrl: string): string | null {
    try {
      if (url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('data:') || url === '#') {
        return null;
      }
      return new URL(url, baseUrl).toString();
    } catch {
      return null;
    }
  }
}
