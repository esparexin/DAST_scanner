import type { PayloadRegistry } from '../registry/payload-registry.js';
import { SQLI_CATALOG } from './sqli.catalog.js';
import { XSS_CATALOG } from './xss.catalog.js';
import { TRAVERSAL_CATALOG } from './traversal.catalog.js';
import { AUTH_CATALOG } from './auth.catalog.js';
import { NOSQL_CATALOG } from './nosql.catalog.js';
import { SSTI_CATALOG } from './ssti.catalog.js';
import { XXE_CATALOG } from './xxe.catalog.js';

export * from './sqli.catalog.js';
export * from './xss.catalog.js';
export * from './traversal.catalog.js';
export * from './auth.catalog.js';
export * from './nosql.catalog.js';
export * from './ssti.catalog.js';
export * from './xxe.catalog.js';

export function loadDefaultCatalogs(registry: PayloadRegistry): void {
  registry.registerAll(SQLI_CATALOG);
  registry.registerAll(XSS_CATALOG);
  registry.registerAll(TRAVERSAL_CATALOG);
  registry.registerAll(AUTH_CATALOG);
  registry.registerAll(NOSQL_CATALOG);
  registry.registerAll(SSTI_CATALOG);
  registry.registerAll(XXE_CATALOG);
  registry.setCatalogVersion('1.2.0');
}
