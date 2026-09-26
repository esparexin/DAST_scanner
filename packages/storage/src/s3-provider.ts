import crypto from 'node:crypto';
import type { StorageConfig, StorageProvider, StoragePutResult } from './types.js';

export class S3StorageProvider implements StorageProvider {
  private readonly bucket: string;
  private readonly endpoint: string;
  private readonly region: string;
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private readonly forcePathStyle: boolean;

  constructor(config: Partial<StorageConfig>) {
    this.bucket = config.bucket ?? process.env['S3_BUCKET'] ?? 'securityscan-evidence';
    this.endpoint = (config.endpoint ?? process.env['S3_ENDPOINT'] ?? 'http://localhost:9000').replace(/\/+$/, '');
    this.region = config.region ?? process.env['S3_REGION'] ?? 'us-east-1';
    this.accessKeyId = config.accessKeyId ?? process.env['S3_ACCESS_KEY'] ?? process.env['AWS_ACCESS_KEY_ID'] ?? 'minioadmin';
    this.secretAccessKey = config.secretAccessKey ?? process.env['S3_SECRET_KEY'] ?? process.env['AWS_SECRET_ACCESS_KEY'] ?? 'minioadmin';
    this.forcePathStyle = config.forcePathStyle ?? true;
  }

  private getUrl(key: string): URL {
    const cleanKey = key.replace(/^\/+/, '');
    if (this.forcePathStyle) {
      return new URL(`${this.endpoint}/${this.bucket}/${cleanKey}`);
    }
    const endpointUrl = new URL(this.endpoint);
    return new URL(`${endpointUrl.protocol}//${this.bucket}.${endpointUrl.host}/${cleanKey}`);
  }

  private hmac(key: Buffer | string, data: string): Buffer {
    return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
  }

  private hash(data: Buffer | string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private getSigningKey(dateStamp: string): Buffer {
    const kDate = this.hmac(`AWS4${this.secretAccessKey}`, dateStamp);
    const kRegion = this.hmac(kDate, this.region);
    const kService = this.hmac(kRegion, 's3');
    return this.hmac(kService, 'aws4_request');
  }

  private signRequest(
    method: string,
    url: URL,
    headers: Record<string, string>,
    payloadHash: string,
  ): Record<string, string> {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.substring(0, 8);

    const signedHeadersList = ['host', 'x-amz-content-sha256', 'x-amz-date'];
    const requestHeaders: Record<string, string> = {
      ...headers,
      host: url.host,
      'x-amz-date': amzDate,
      'x-amz-content-sha256': payloadHash,
    };

    const canonicalHeaders = signedHeadersList
      .sort()
      .map((h) => `${h}:${requestHeaders[h]?.trim() ?? ''}\n`)
      .join('');
    const signedHeaders = signedHeadersList.sort().join(';');

    const canonicalRequest = [
      method,
      url.pathname,
      url.searchParams.toString(),
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join('\n');

    const credentialScope = `${dateStamp}/${this.region}/s3/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      this.hash(canonicalRequest),
    ].join('\n');

    const signingKey = this.getSigningKey(dateStamp);
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

    requestHeaders['Authorization'] = `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return requestHeaders;
  }

  async putObject(
    key: string,
    data: Buffer | Uint8Array | string,
    contentType = 'application/octet-stream',
  ): Promise<StoragePutResult> {
    const buffer = Buffer.isBuffer(data)
      ? data
      : typeof data === 'string'
        ? Buffer.from(data, 'utf-8')
        : Buffer.from(data);

    const url = this.getUrl(key);
    const payloadHash = this.hash(buffer);
    const headers = this.signRequest('PUT', url, { 'content-type': contentType }, payloadHash);

    const res = await fetch(url.toString(), {
      method: 'PUT',
      headers,
      body: buffer,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`S3 PUT failed with status ${res.status}: ${errText}`);
    }

    const etag = res.headers.get('etag') ?? `"${payloadHash}"`;

    return {
      key,
      size: buffer.length,
      etag,
      url: url.toString(),
      contentType,
      uploadedAt: new Date(),
    };
  }

  async getObject(key: string): Promise<Buffer | null> {
    const url = this.getUrl(key);
    const payloadHash = this.hash('');
    const headers = this.signRequest('GET', url, {}, payloadHash);

    const res = await fetch(url.toString(), {
      method: 'GET',
      headers,
    });

    if (res.status === 404) {
      return null;
    }

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`S3 GET failed with status ${res.status}: ${errText}`);
    }

    const arrayBuffer = await res.arrayBuffer();
    return Buffer.from(arrayBuffer);
  }

  async deleteObject(key: string): Promise<boolean> {
    const url = this.getUrl(key);
    const payloadHash = this.hash('');
    const headers = this.signRequest('DELETE', url, {}, payloadHash);

    const res = await fetch(url.toString(), {
      method: 'DELETE',
      headers,
    });

    return res.status === 204 || res.status === 200 || res.status === 404;
  }

  async exists(key: string): Promise<boolean> {
    const url = this.getUrl(key);
    const payloadHash = this.hash('');
    const headers = this.signRequest('HEAD', url, {}, payloadHash);

    const res = await fetch(url.toString(), {
      method: 'HEAD',
      headers,
    });

    return res.ok;
  }

  async getPresignedUrl(key: string, expiresInSeconds = 3600): Promise<string> {
    const url = this.getUrl(key);
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.substring(0, 8);
    const credentialScope = `${dateStamp}/${this.region}/s3/aws4_request`;

    url.searchParams.set('X-Amz-Algorithm', 'AWS4-HMAC-SHA256');
    url.searchParams.set('X-Amz-Credential', `${this.accessKeyId}/${credentialScope}`);
    url.searchParams.set('X-Amz-Date', amzDate);
    url.searchParams.set('X-Amz-Expires', expiresInSeconds.toString());
    url.searchParams.set('X-Amz-SignedHeaders', 'host');

    const canonicalQuery = Array.from(url.searchParams.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');

    const canonicalRequest = [
      'GET',
      url.pathname,
      canonicalQuery,
      `host:${url.host}\n`,
      'host',
      'UNSIGNED-PAYLOAD',
    ].join('\n');

    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      this.hash(canonicalRequest),
    ].join('\n');

    const signingKey = this.getSigningKey(dateStamp);
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

    url.searchParams.set('X-Amz-Signature', signature);

    return url.toString();
  }
}
