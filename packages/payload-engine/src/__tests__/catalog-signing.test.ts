import { describe, it, expect } from 'vitest';
import { CatalogSigner } from '../signing/catalog-signer.js';
import { SQLI_CATALOG, XSS_CATALOG, TRAVERSAL_CATALOG, AUTH_CATALOG } from '../catalogs/index.js';

describe('CatalogSigner', () => {
  const allPayloads = [...SQLI_CATALOG, ...XSS_CATALOG, ...TRAVERSAL_CATALOG, ...AUTH_CATALOG];

  it('generates a valid RSA key pair', () => {
    const keys = CatalogSigner.generateKeyPair();
    expect(keys.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keys.privateKey).toContain('BEGIN PRIVATE KEY');
  });

  it('signs a catalog and produces a manifest with correct metadata', () => {
    const keys = CatalogSigner.generateKeyPair();
    const manifest = CatalogSigner.signCatalog(allPayloads, '1.1.0', keys.privateKey);

    expect(manifest.version).toBe('1.1.0');
    expect(manifest.payloadCount).toBe(allPayloads.length);
    expect(manifest.payloadIds.length).toBe(allPayloads.length);
    expect(manifest.contentHash).toHaveLength(64); // SHA-256 hex
    expect(manifest.signature.length).toBeGreaterThan(100); // Base64 RSA sig
    expect(manifest.generatedAt).toBeTruthy();
  });

  it('verifies a valid signed catalog', () => {
    const keys = CatalogSigner.generateKeyPair();
    const manifest = CatalogSigner.signCatalog(allPayloads, '1.1.0', keys.privateKey);

    const valid = CatalogSigner.verifyCatalog(manifest, allPayloads, keys.publicKey);
    expect(valid).toBe(true);
  });

  it('rejects a tampered catalog (payload removed)', () => {
    const keys = CatalogSigner.generateKeyPair();
    const manifest = CatalogSigner.signCatalog(allPayloads, '1.1.0', keys.privateKey);

    // Remove one payload
    const tampered = allPayloads.slice(1);
    const valid = CatalogSigner.verifyCatalog(manifest, tampered, keys.publicKey);
    expect(valid).toBe(false);
  });

  it('rejects a manifest with forged signature', () => {
    const keys = CatalogSigner.generateKeyPair();
    const manifest = CatalogSigner.signCatalog(allPayloads, '1.1.0', keys.privateKey);

    // Use a different key pair for verification
    const otherKeys = CatalogSigner.generateKeyPair();
    const valid = CatalogSigner.verifyCatalog(manifest, allPayloads, otherKeys.publicKey);
    expect(valid).toBe(false);
  });

  it('produces deterministic content hash for same payloads', () => {
    const hash1 = CatalogSigner.computeContentHash(allPayloads);
    const hash2 = CatalogSigner.computeContentHash([...allPayloads].reverse());
    expect(hash1).toBe(hash2); // Order-independent because sorted internally
  });
});
