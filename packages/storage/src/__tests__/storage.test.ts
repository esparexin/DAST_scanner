import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  LocalStorageProvider,
  S3StorageProvider,
  createStorageProvider,
} from '../index.js';

describe('LocalStorageProvider', () => {
  let tmpDir: string;
  let provider: LocalStorageProvider;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'storage-test-'));
    provider = new LocalStorageProvider(tmpDir);
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  });

  it('puts and gets an object successfully', async () => {
    const result = await provider.putObject('scans/123/evidence.txt', 'evidence payload', 'text/plain');
    expect(result.key).toBe('scans/123/evidence.txt');
    expect(result.size).toBe(16);
    expect(result.etag).toBeDefined();

    const data = await provider.getObject('scans/123/evidence.txt');
    expect(data).not.toBeNull();
    expect(data?.toString('utf-8')).toBe('evidence payload');
  });

  it('checks existence of object', async () => {
    expect(await provider.exists('non-existent.txt')).toBe(false);
    await provider.putObject('test.json', JSON.stringify({ ok: true }));
    expect(await provider.exists('test.json')).toBe(true);
  });

  it('deletes an object', async () => {
    await provider.putObject('temp.bin', Buffer.from([1, 2, 3]));
    expect(await provider.exists('temp.bin')).toBe(true);

    const deleted = await provider.deleteObject('temp.bin');
    expect(deleted).toBe(true);
    expect(await provider.exists('temp.bin')).toBe(false);
  });

  it('returns null for non-existent file', async () => {
    const result = await provider.getObject('missing/file.png');
    expect(result).toBeNull();
  });

  it('prevents path traversal outside storage base directory', async () => {
    await expect(provider.putObject('../../sensitive.txt', 'evil')).rejects.toThrow(
      /Path traversal attempt detected/,
    );
  });
});

describe('S3StorageProvider', () => {
  it('generates valid SigV4 presigned URLs', async () => {
    const provider = new S3StorageProvider({
      bucket: 'test-bucket',
      endpoint: 'http://localhost:9000',
      accessKeyId: 'test-access',
      secretAccessKey: 'test-secret-key-1234567890',
      region: 'us-east-1',
      forcePathStyle: true,
    });

    const presignedUrl = await provider.getPresignedUrl('evidence/scan-1/screenshot.png', 1800);
    expect(presignedUrl).toContain('http://localhost:9000/test-bucket/evidence/scan-1/screenshot.png?');
    expect(presignedUrl).toContain('X-Amz-Algorithm=AWS4-HMAC-SHA256');
    expect(presignedUrl).toContain('X-Amz-Credential=test-access%2F');
    expect(presignedUrl).toContain('X-Amz-Signature=');
    expect(presignedUrl).toContain('X-Amz-Expires=1800');
  });
});

describe('createStorageProvider factory', () => {
  it('returns LocalStorageProvider by default', () => {
    const provider = createStorageProvider({ provider: 'local' });
    expect(provider).toBeInstanceOf(LocalStorageProvider);
  });

  it('returns S3StorageProvider when provider is s3', () => {
    const provider = createStorageProvider({ provider: 's3', bucket: 'my-bucket' });
    expect(provider).toBeInstanceOf(S3StorageProvider);
  });
});
