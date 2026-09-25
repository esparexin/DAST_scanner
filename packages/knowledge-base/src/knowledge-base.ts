import { OWASP_TOP_10_2021, type OwaspTop10Item } from './taxonomies/owasp-top10.js';
import { OWASP_API_SECURITY_2023, type OwaspApiItem } from './taxonomies/owasp-api.js';
import { WSTG_V42, type WstgItem } from './taxonomies/wstg.js';
import { ASVS_V403, type AsvsItem } from './taxonomies/asvs.js';
import { CWE_CATALOG, type CweItem } from './taxonomies/cwe.js';
import { PORTSWIGGER_REFERENCES, type PortSwiggerTopic } from './taxonomies/portswigger.js';
import { calculateCvss31, parseCvssVector, type CvssCalculationResult } from './cvss/calculator.js';

export interface ComprehensiveTaxonomyMapping {
  owasp: OwaspTop10Item[];
  owaspApi: OwaspApiItem[];
  wstg: WstgItem[];
  asvs: AsvsItem[];
  cwe: CweItem[];
  portswigger: PortSwiggerTopic[];
  cvss?: CvssCalculationResult;
}

export class SecurityKnowledgeBase {
  static getOwaspTop10(id: string): OwaspTop10Item | undefined {
    return OWASP_TOP_10_2021[id];
  }

  static getOwaspApi(id: string): OwaspApiItem | undefined {
    return OWASP_API_SECURITY_2023[id];
  }

  static getWstg(id: string): WstgItem | undefined {
    return WSTG_V42[id];
  }

  static getAsvs(id: string): AsvsItem | undefined {
    return ASVS_V403[id];
  }

  static getCwe(id: string): CweItem | undefined {
    return CWE_CATALOG[id];
  }

  static getPortSwigger(topicId: string): PortSwiggerTopic | undefined {
    return PORTSWIGGER_REFERENCES[topicId];
  }

  static calculateCvss(vectorString: string): CvssCalculationResult {
    const metrics = parseCvssVector(vectorString);
    return calculateCvss31(metrics);
  }

  static resolveMapping(params: {
    owaspIds?: string[];
    owaspApiIds?: string[];
    wstgIds?: string[];
    asvsIds?: string[];
    cweIds?: string[];
    portswiggerTopics?: string[];
    cvssVector?: string;
  }): ComprehensiveTaxonomyMapping {
    return {
      owasp: (params.owaspIds ?? []).map((id) => this.getOwaspTop10(id)).filter((x): x is OwaspTop10Item => !!x),
      owaspApi: (params.owaspApiIds ?? []).map((id) => this.getOwaspApi(id)).filter((x): x is OwaspApiItem => !!x),
      wstg: (params.wstgIds ?? []).map((id) => this.getWstg(id)).filter((x): x is WstgItem => !!x),
      asvs: (params.asvsIds ?? []).map((id) => this.getAsvs(id)).filter((x): x is AsvsItem => !!x),
      cwe: (params.cweIds ?? []).map((id) => this.getCwe(id)).filter((x): x is CweItem => !!x),
      portswigger: (params.portswiggerTopics ?? []).map((t) => this.getPortSwigger(t)).filter((x): x is PortSwiggerTopic => !!x),
      cvss: params.cvssVector ? this.calculateCvss(params.cvssVector) : undefined,
    };
  }
}
