import type { IPayloadDefinition, PayloadStatus } from '../types/payload-definition.js';
import { PayloadContextIndex } from './context-index.js';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('payload-registry');

export class PayloadRegistry {
  private readonly index = new PayloadContextIndex();
  private catalogVersion: string = '1.0.0';

  register(payload: IPayloadDefinition): void {
    this.index.index(payload);
    logger.debug({ id: payload.id, category: payload.category }, 'Payload registered in catalog');
  }

  registerAll(payloads: IPayloadDefinition[]): void {
    for (const p of payloads) {
      this.register(p);
    }
  }

  get(id: string): IPayloadDefinition | undefined {
    return this.index.get(id);
  }

  getAll(filterStatus?: PayloadStatus): IPayloadDefinition[] {
    const all = this.index.getAll();
    if (!filterStatus) return all;
    return all.filter((p) => p.status === filterStatus);
  }

  getActive(): IPayloadDefinition[] {
    return this.getAll('ACTIVE');
  }

  size(): number {
    return this.index.getAll().length;
  }

  getIndex(): PayloadContextIndex {
    return this.index;
  }

  setCatalogVersion(version: string): void {
    this.catalogVersion = version;
  }

  getCatalogVersion(): string {
    return this.catalogVersion;
  }

  clear(): void {
    this.index.clear();
  }
}
