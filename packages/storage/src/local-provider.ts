import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { StorageProvider, StoragePutResult } from './types.js';

export class LocalStorageProvider implements StorageProvider {
  private readonly baseDir: string;

  constructor(baseDir?: string) {
    this.baseDir = path.resolve(baseDir ?? process.env['LOCAL_STORAGE_PATH'] ?? './uploads');
  }

  private resolveSafePath(key: string): string {
    if (key.includes('..')) {
      throw new Error(`Path traversal attempt detected in storage key: ${key}`);
    }
    const cleanKey = key.replace(/^[\\/]+/, '');
    const resolved = path.resolve(this.baseDir, cleanKey);
    if (!resolved.startsWith(this.baseDir)) {
      throw new Error(`Path traversal attempt detected in storage key: ${key}`);
    }
    return resolved;
  }

  async putObject(
    key: string,
    data: Buffer | Uint8Array | string,
    contentType = 'application/octet-stream',
  ): Promise<StoragePutResult> {
    const fullPath = this.resolveSafePath(key);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });

    const buffer = Buffer.isBuffer(data)
      ? data
      : typeof data === 'string'
        ? Buffer.from(data, 'utf-8')
        : Buffer.from(data);

    await fs.writeFile(fullPath, buffer);

    const hash = crypto.createHash('md5').update(buffer).digest('hex');

    return {
      key,
      size: buffer.length,
      etag: `"${hash}"`,
      url: `file://${fullPath}`,
      contentType,
      uploadedAt: new Date(),
    };
  }

  async getObject(key: string): Promise<Buffer | null> {
    try {
      const fullPath = this.resolveSafePath(key);
      return await fs.readFile(fullPath);
    } catch (err: any) {
      if (err.code === 'ENOENT') {
        return null;
      }
      throw err;
    }
  }

  async deleteObject(key: string): Promise<boolean> {
    try {
      const fullPath = this.resolveSafePath(key);
      await fs.unlink(fullPath);
      return true;
    } catch (err: any) {
      if (err.code === 'ENOENT') {
        return false;
      }
      throw err;
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const fullPath = this.resolveSafePath(key);
      await fs.stat(fullPath);
      return true;
    } catch {
      return false;
    }
  }

  async getPresignedUrl(key: string, _expiresInSeconds = 3600): Promise<string> {
    const fullPath = this.resolveSafePath(key);
    return `file://${fullPath}`;
  }
}
