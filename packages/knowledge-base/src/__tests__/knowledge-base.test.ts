import { describe, it, expect } from 'vitest';
import {
  SecurityKnowledgeBase,
  calculateCvss31,
  formatCvssVector,
  parseCvssVector,
} from '../index.js';

describe('SecurityKnowledgeBase Taxonomy Lookups', () => {
  it('resolves OWASP Top 10 items correctly', () => {
    const item = SecurityKnowledgeBase.getOwaspTop10('A03:2021');
    expect(item).toBeDefined();
    expect(item?.name).toBe('Injection');
  });

  it('resolves OWASP API Security items correctly', () => {
    const item = SecurityKnowledgeBase.getOwaspApi('API1:2023');
    expect(item).toBeDefined();
    expect(item?.name).toBe('Broken Object Level Authorization');
  });

  it('resolves WSTG testing items correctly', () => {
    const item = SecurityKnowledgeBase.getWstg('WSTG-INPV-05');
    expect(item).toBeDefined();
    expect(item?.name).toBe('Testing for SQL Injection');
  });

  it('resolves ASVS verification items correctly', () => {
    const item = SecurityKnowledgeBase.getAsvs('V5.3.4');
    expect(item).toBeDefined();
    expect(item?.requirement).toContain('parameterized queries');
  });

  it('resolves CWE catalog items correctly', () => {
    const item = SecurityKnowledgeBase.getCwe('CWE-89');
    expect(item).toBeDefined();
    expect(item?.name).toContain('SQL Injection');
  });

  it('resolves PortSwigger topics correctly', () => {
    const item = SecurityKnowledgeBase.getPortSwigger('sql-injection');
    expect(item).toBeDefined();
    expect(item?.url).toBe('https://portswigger.net/web-security/sql-injection');
  });

  it('resolves unified comprehensive mapping', () => {
    const mapping = SecurityKnowledgeBase.resolveMapping({
      owaspIds: ['A03:2021'],
      owaspApiIds: ['API8:2023'],
      wstgIds: ['WSTG-INPV-05'],
      asvsIds: ['V5.3.4'],
      cweIds: ['CWE-89'],
      portswiggerTopics: ['sql-injection'],
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    });

    expect(mapping.owasp).toHaveLength(1);
    expect(mapping.owaspApi).toHaveLength(1);
    expect(mapping.wstg).toHaveLength(1);
    expect(mapping.asvs).toHaveLength(1);
    expect(mapping.cwe).toHaveLength(1);
    expect(mapping.portswigger).toHaveLength(1);
    expect(mapping.cvss?.baseScore).toBe(9.8);
    expect(mapping.cvss?.severity).toBe('CRITICAL');
  });
});

describe('CVSS v3.1 Calculator', () => {
  it('calculates Critical SQLi score correctly (9.8)', () => {
    const metrics = {
      attackVector: 'NETWORK' as const,
      attackComplexity: 'LOW' as const,
      privilegesRequired: 'NONE' as const,
      userInteraction: 'NONE' as const,
      scope: 'UNCHANGED' as const,
      confidentiality: 'HIGH' as const,
      integrity: 'HIGH' as const,
      availability: 'HIGH' as const,
    };
    const result = calculateCvss31(metrics);
    expect(result.baseScore).toBe(9.8);
    expect(result.severity).toBe('CRITICAL');
    expect(result.vectorString).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });

  it('calculates Medium Reflected XSS score correctly (6.1)', () => {
    const metrics = {
      attackVector: 'NETWORK' as const,
      attackComplexity: 'LOW' as const,
      privilegesRequired: 'NONE' as const,
      userInteraction: 'REQUIRED' as const,
      scope: 'CHANGED' as const,
      confidentiality: 'LOW' as const,
      integrity: 'LOW' as const,
      availability: 'NONE' as const,
    };
    const result = calculateCvss31(metrics);
    expect(result.baseScore).toBe(6.1);
    expect(result.severity).toBe('MEDIUM');
  });

  it('parses vector string back to metrics accurately', () => {
    const vec = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
    const parsed = parseCvssVector(vec);
    expect(parsed.attackVector).toBe('NETWORK');
    expect(parsed.userInteraction).toBe('REQUIRED');
    expect(parsed.scope).toBe('CHANGED');
    expect(formatCvssVector(parsed)).toBe(vec);
  });
});
