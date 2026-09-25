export interface SpaRouteDiscovery {
  url: string;
  pageTitle: string;
  discoveredLinks: string[];
  discoveredForms: Array<{
    action: string;
    method: string;
    inputs: string[];
  }>;
  xhrRequestsIntercepted: Array<{
    url: string;
    method: string;
  }>;
  domXssSinksObserved: string[];
}

export interface IBrowserDriver {
  navigateAndExtract(url: string, timeoutMs?: number): Promise<SpaRouteDiscovery>;
}
