import { describe, it, expect } from 'vitest';
import { LinkExtractor } from '../link-extractor.js';

describe('LinkExtractor', () => {
  const extractor = new LinkExtractor();

  it('extracts href links', () => {
    const html = '<a href="/about">About</a><a href="https://example.com/contact">Contact</a>';
    const links = extractor.extractLinks(html, 'https://example.com');
    expect(links).toContain('https://example.com/about');
    expect(links).toContain('https://example.com/contact');
  });

  it('extracts form actions', () => {
    const html = '<form action="/login" method="post"><input name="user"></form>';
    const links = extractor.extractLinks(html, 'https://example.com');
    expect(links).toContain('https://example.com/login');
  });

  it('ignores javascript: and mailto: links', () => {
    const html = '<a href="javascript:void(0)">X</a><a href="mailto:a@b.com">M</a>';
    const links = extractor.extractLinks(html, 'https://example.com');
    expect(links).toHaveLength(0);
  });

  it('extracts forms with inputs', () => {
    const html = '<form action="/search" method="GET"><input name="q" type="text"><input name="page" type="hidden"></form>';
    const forms = extractor.extractForms(html, 'https://example.com');
    expect(forms).toHaveLength(1);
    expect(forms[0]!.action).toBe('https://example.com/search');
    expect(forms[0]!.method).toBe('GET');
    expect(forms[0]!.inputs).toHaveLength(2);
  });

  it('extracts API URLs from JavaScript', () => {
    const js = `fetch("/api/users"); axios.get("/v1/items");`;
    const urls = extractor.extractJsUrls(js, 'https://example.com');
    expect(urls).toContain('https://example.com/api/users');
    expect(urls).toContain('https://example.com/v1/items');
  });
});
