import type { IBrowserDriver, SpaRouteDiscovery } from './types.js';

/**
 * Test / Mock Browser Driver simulating DOM execution
 */
export class MockBrowserDriver implements IBrowserDriver {
  async navigateAndExtract(url: string): Promise<SpaRouteDiscovery> {
    return {
      url,
      pageTitle: 'Single Page Application Dashboard',
      discoveredLinks: [`${url}/settings`, `${url}/profile`],
      discoveredForms: [
        {
          action: `${url}/api/v1/update`,
          method: 'POST',
          inputs: ['name', 'email'],
        },
      ],
      xhrRequestsIntercepted: [
        { url: `${url}/api/v1/user/me`, method: 'GET' },
        { url: `${url}/api/v1/analytics`, method: 'POST' },
      ],
      domXssSinksObserved: ['location.hash -> document.write'],
    };
  }
}
