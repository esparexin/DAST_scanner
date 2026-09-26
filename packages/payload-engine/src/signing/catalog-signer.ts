import { createHash, createSign, createVerify, generateKeyPairSync } from 'node:crypto';
import type {
  ISecurityRule,
  SecurityIntelligencePackage,
  SecurityIntelligenceManifest,
} from '@securityscan/contracts';
import type { IPayloadDefinition } from '../types/payload-definition.js';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('catalog-signing');

export interface CatalogManifest {
  version: string;
  generatedAt: string;
  payloadCount: number;
  payloadIds: string[];
  contentHash: string;
  signature: string;
}

export interface CatalogKeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Signed Catalog & Security Intelligence Package Distribution.
 *
 * Generates manifests with Ed25519 / RSA-PSS digital signatures to ensure
 * catalog and intelligence package integrity and authenticity.
 */
export class CatalogSigner {
  /**
   * Generate a new RSA key pair for catalog/package signing.
   * In production, keys would be managed via HSM/KMS.
   */
  static generateKeyPair(): CatalogKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
  }

  /**
   * Generate a signed manifest for a set of payload definitions.
   */
  static signCatalog(
    payloads: IPayloadDefinition[],
    version: string,
    privateKey: string,
  ): CatalogManifest {
    const payloadIds = payloads.map((p) => p.id).sort();
    const contentHash = CatalogSigner.computeContentHash(payloads);

    const dataToSign = `${version}|${payloadIds.join(',')}|${contentHash}`;
    const signer = createSign('SHA256');
    signer.update(dataToSign);
    const signature = signer.sign(privateKey, 'base64');

    logger.info(
      { version, payloadCount: payloads.length, contentHash: contentHash.slice(0, 16) },
      'Catalog signed successfully',
    );

    return {
      version,
      generatedAt: new Date().toISOString(),
      payloadCount: payloads.length,
      payloadIds,
      contentHash,
      signature,
    };
  }

  /**
   * Verify a catalog manifest against its signature using the public key.
   */
  static verifyCatalog(
    manifest: CatalogManifest,
    payloads: IPayloadDefinition[],
    publicKey: string,
  ): boolean {
    const payloadIds = payloads.map((p) => p.id).sort();
    const contentHash = CatalogSigner.computeContentHash(payloads);

    // Verify ID list matches
    if (payloadIds.join(',') !== manifest.payloadIds.join(',')) {
      logger.warn('Catalog verification failed: payload ID mismatch');
      return false;
    }

    // Verify content hash matches
    if (contentHash !== manifest.contentHash) {
      logger.warn('Catalog verification failed: content hash mismatch');
      return false;
    }

    // Verify signature
    const dataToVerify = `${manifest.version}|${manifest.payloadIds.join(',')}|${manifest.contentHash}`;
    const verifier = createVerify('SHA256');
    verifier.update(dataToVerify);

    const valid = verifier.verify(publicKey, manifest.signature, 'base64');

    if (!valid) {
      logger.warn('Catalog verification failed: invalid signature');
    } else {
      logger.info({ version: manifest.version }, 'Catalog signature verified successfully');
    }

    return valid;
  }

  /**
   * Compute deterministic SHA-256 hash of sorted, serialized payload definitions.
   */
  static computeContentHash(payloads: IPayloadDefinition[]): string {
    const sorted = [...payloads].sort((a, b) => a.id.localeCompare(b.id));
    const serialized = JSON.stringify(
      sorted.map((p) => ({
        id: p.id,
        version: p.version,
        status: p.status,
        category: p.category,
        template: p.template?.raw ?? '',
        detection: p.detection?.strategy ?? '',
        verification: p.verification?.strategy ?? '',
      })),
    );

    return createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Compute deterministic SHA-256 hash of sorted security rules.
   */
  static computeRulesHash(rules: ISecurityRule[]): string {
    const sorted = [...rules].sort((a, b) => a.id.localeCompare(b.id));
    const serialized = JSON.stringify(
      sorted.map((r) => ({
        id: r.id,
        name: r.name,
        category: r.category,
        type: r.type,
        severity: r.severity,
        confidence: r.confidence,
        cwe: [...(r.cwe ?? [])].sort(),
        owasp: [...(r.owasp ?? [])].sort(),
        ruleVersion: r.ruleVersion,
        contentHash: r.contentHash,
      })),
    );
    return createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Compute deterministic composite hash for an entire SecurityIntelligencePackage.
   */
  static computePackageHash(pkg: SecurityIntelligencePackage): string {
    const rulesHash = CatalogSigner.computeRulesHash(pkg.rules);
    const payloadsHash = CatalogSigner.computeContentHash(pkg.payloads as unknown as IPayloadDefinition[]);
    const composite = `${pkg.packageVersion}|${rulesHash}|${payloadsHash}`;
    return createHash('sha256').update(composite).digest('hex');
  }

  /**
   * Sign a composite SecurityIntelligencePackage (rules + payloads + taxonomies).
   */
  static signPackage(
    pkg: SecurityIntelligencePackage,
    privateKey: string,
  ): SecurityIntelligenceManifest {
    const ruleIds = pkg.rules.map((r) => r.id).sort();
    const payloadIds = pkg.payloads.map((p) => p.id).sort();
    const rulesHash = CatalogSigner.computeRulesHash(pkg.rules);
    const payloadsHash = CatalogSigner.computeContentHash(pkg.payloads as unknown as IPayloadDefinition[]);
    const packageHash = CatalogSigner.computePackageHash(pkg);

    const dataToSign = `${pkg.packageVersion}|${packageHash}`;
    const signer = createSign('SHA256');
    signer.update(dataToSign);
    const signature = signer.sign(privateKey, 'base64');

    logger.info(
      { version: pkg.packageVersion, ruleCount: pkg.rules.length, payloadCount: pkg.payloads.length, packageHash },
      'Security intelligence package signed successfully',
    );

    return {
      packageVersion: pkg.packageVersion,
      generatedAt: new Date().toISOString(),
      ruleCount: pkg.rules.length,
      ruleIds,
      payloadCount: pkg.payloads.length,
      payloadIds,
      rulesHash,
      payloadsHash,
      packageHash,
      signature,
    };
  }

  /**
   * Cryptographically verify a SecurityIntelligencePackage against its manifest.
   */
  static verifyPackage(
    manifest: SecurityIntelligenceManifest,
    pkg: SecurityIntelligencePackage,
    publicKey: string,
  ): boolean {
    const ruleIds = pkg.rules.map((r) => r.id).sort();
    const payloadIds = pkg.payloads.map((p) => p.id).sort();
    const rulesHash = CatalogSigner.computeRulesHash(pkg.rules);
    const payloadsHash = CatalogSigner.computeContentHash(pkg.payloads as unknown as IPayloadDefinition[]);
    const packageHash = CatalogSigner.computePackageHash(pkg);

    if (ruleIds.join(',') !== manifest.ruleIds.join(',')) {
      logger.warn('Package verification failed: rule ID mismatch');
      return false;
    }
    if (payloadIds.join(',') !== manifest.payloadIds.join(',')) {
      logger.warn('Package verification failed: payload ID mismatch');
      return false;
    }
    if (
      rulesHash !== manifest.rulesHash ||
      payloadsHash !== manifest.payloadsHash ||
      packageHash !== manifest.packageHash
    ) {
      logger.warn('Package verification failed: content hash mismatch');
      return false;
    }

    const dataToVerify = `${manifest.packageVersion}|${manifest.packageHash}`;
    const verifier = createVerify('SHA256');
    verifier.update(dataToVerify);
    const valid = verifier.verify(publicKey, manifest.signature, 'base64');

    if (!valid) {
      logger.warn('Package verification failed: invalid signature');
    } else {
      logger.info({ version: manifest.packageVersion }, 'Package signature verified successfully');
    }
    return valid;
  }
}
