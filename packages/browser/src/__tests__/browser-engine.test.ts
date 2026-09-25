import { describe, it, expect } from 'vitest';
import { BrowserEngine, MockBrowserDriver } from '../index.js';

describe('BrowserEngine for SPAs', () => {
  it('extracts dynamically rendered links, forms, and intercepted API calls', async () => {
    const driver = new MockBrowserDriver();
    const engine = new BrowserEngine(driver);

    const result = await engine.analyzeSpa('https://app.example.com');
    expect(result.pageTitle).toContain('Single Page Application');
    expect(result.discoveredLinks).toHaveLength(2);
    expect(result.xhrRequestsIntercepted).toHaveLength(2);
    expect(result.xhrRequestsIntercepted[0]?.url).toContain('/api/v1/user/me');
    expect(result.domXssSinksObserved).toHaveLength(1);
  });
});
