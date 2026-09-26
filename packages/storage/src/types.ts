export interface StoragePutResult {
  key: string;
  size: number;
  etag?: string;
  url?: string;
  contentType: string;
  uploadedAt: Date;
}

export interface StorageObjectMetadata {
  key: string;
  size: number;
  contentType: string;
  lastModified: Date;
  metadata?: Record<string, string>;
}

export interface StorageConfig {
  provider: 'local' | 's3';
  localDir?: string;
  bucket?: string;
  endpoint?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  forcePathStyle?: boolean;
}

export interface StorageProvider {
  putObject(
    key: string,
    data: Buffer | Uint8Array | string,
    contentType?: string,
    metadata?: Record<string, string>,
  ): Promise<StoragePutResult>;
  getObject(key: string): Promise<Buffer | null>;
  deleteObject(key: string): Promise<boolean>;
  exists(key: string): Promise<boolean>;
  getPresignedUrl(key: string, expiresInSeconds?: number): Promise<string>;
}
