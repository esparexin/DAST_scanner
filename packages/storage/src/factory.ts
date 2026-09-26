import type { StorageConfig, StorageProvider } from './types.js';
import { LocalStorageProvider } from './local-provider.js';
import { S3StorageProvider } from './s3-provider.js';

export function createStorageProvider(config?: Partial<StorageConfig>): StorageProvider {
  const providerType =
    config?.provider ??
    (process.env['STORAGE_PROVIDER'] as 'local' | 's3' | undefined) ??
    (process.env['S3_BUCKET'] || process.env['AWS_ACCESS_KEY_ID'] ? 's3' : 'local');

  if (providerType === 's3') {
    return new S3StorageProvider(config ?? {});
  }

  return new LocalStorageProvider(config?.localDir);
}
