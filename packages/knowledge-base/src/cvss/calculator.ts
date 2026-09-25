/**
 * CVSS v3.1 Base Score Calculator conforming to FIRST.org specification
 */

export type AttackVector = 'NETWORK' | 'ADJACENT' | 'LOCAL' | 'PHYSICAL';
export type AttackComplexity = 'LOW' | 'HIGH';
export type PrivilegesRequired = 'NONE' | 'LOW' | 'HIGH';
export type UserInteraction = 'NONE' | 'REQUIRED';
export type Scope = 'UNCHANGED' | 'CHANGED';
export type ImpactMetric = 'NONE' | 'LOW' | 'HIGH';

export interface CvssMetrics {
  attackVector: AttackVector;
  attackComplexity: AttackComplexity;
  privilegesRequired: PrivilegesRequired;
  userInteraction: UserInteraction;
  scope: Scope;
  confidentiality: ImpactMetric;
  integrity: ImpactMetric;
  availability: ImpactMetric;
}

export interface CvssCalculationResult {
  baseScore: number;
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  vectorString: string;
  impactScore: number;
  exploitabilityScore: number;
}

const AV_WEIGHTS: Record<AttackVector, number> = {
  NETWORK: 0.85,
  ADJACENT: 0.62,
  LOCAL: 0.55,
  PHYSICAL: 0.2,
};

const AC_WEIGHTS: Record<AttackComplexity, number> = {
  LOW: 0.77,
  HIGH: 0.44,
};

const PR_WEIGHTS: Record<Scope, Record<PrivilegesRequired, number>> = {
  UNCHANGED: {
    NONE: 0.85,
    LOW: 0.62,
    HIGH: 0.27,
  },
  CHANGED: {
    NONE: 0.85,
    LOW: 0.68,
    HIGH: 0.5,
  },
};

const UI_WEIGHTS: Record<UserInteraction, number> = {
  NONE: 0.85,
  REQUIRED: 0.62,
};

const IMPACT_WEIGHTS: Record<ImpactMetric, number> = {
  NONE: 0.0,
  LOW: 0.22,
  HIGH: 0.56,
};

function roundup(val: number): number {
  const rounded = Math.round(val * 100000);
  if (rounded % 10000 === 0) {
    return rounded / 100000;
  }
  return (Math.floor(rounded / 10000) + 1) / 10;
}

export function calculateCvss31(metrics: CvssMetrics): CvssCalculationResult {
  const av = AV_WEIGHTS[metrics.attackVector];
  const ac = AC_WEIGHTS[metrics.attackComplexity];
  const pr = PR_WEIGHTS[metrics.scope][metrics.privilegesRequired];
  const ui = UI_WEIGHTS[metrics.userInteraction];

  const exploitability = roundup(8.22 * av * ac * pr * ui);

  const c = IMPACT_WEIGHTS[metrics.confidentiality];
  const i = IMPACT_WEIGHTS[metrics.integrity];
  const a = IMPACT_WEIGHTS[metrics.availability];

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  let impact: number;
  if (metrics.scope === 'UNCHANGED') {
    impact = roundup(6.42 * iss);
  } else {
    impact = roundup(7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15));
  }

  let baseScore = 0;
  if (impact > 0) {
    if (metrics.scope === 'UNCHANGED') {
      baseScore = Math.min(10.0, roundup(impact + exploitability));
    } else {
      baseScore = Math.min(10.0, roundup(1.08 * (impact + exploitability)));
    }
  }

  let severity: CvssCalculationResult['severity'];
  if (baseScore === 0) severity = 'NONE';
  else if (baseScore <= 3.9) severity = 'LOW';
  else if (baseScore <= 6.9) severity = 'MEDIUM';
  else if (baseScore <= 8.9) severity = 'HIGH';
  else severity = 'CRITICAL';

  const vectorString = formatCvssVector(metrics);

  return {
    baseScore,
    severity,
    vectorString,
    impactScore: impact,
    exploitabilityScore: exploitability,
  };
}

export function formatCvssVector(m: CvssMetrics): string {
  const av = m.attackVector === 'NETWORK' ? 'N' : m.attackVector === 'ADJACENT' ? 'A' : m.attackVector === 'LOCAL' ? 'L' : 'P';
  const ac = m.attackComplexity === 'LOW' ? 'L' : 'H';
  const pr = m.privilegesRequired === 'NONE' ? 'N' : m.privilegesRequired === 'LOW' ? 'L' : 'H';
  const ui = m.userInteraction === 'NONE' ? 'N' : 'R';
  const s = m.scope === 'UNCHANGED' ? 'U' : 'C';
  const c = m.confidentiality === 'NONE' ? 'N' : m.confidentiality === 'LOW' ? 'L' : 'H';
  const i = m.integrity === 'NONE' ? 'N' : m.integrity === 'LOW' ? 'L' : 'H';
  const a = m.availability === 'NONE' ? 'N' : m.availability === 'LOW' ? 'L' : 'H';

  return `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;
}

export function parseCvssVector(vector: string): CvssMetrics {
  const parts = vector.replace(/^CVSS:3\.[01]\//, '').split('/');
  const dict: Record<string, string> = {};
  for (const part of parts) {
    const [k, v] = part.split(':');
    if (k && v) dict[k] = v;
  }

  const avMap: Record<string, AttackVector> = { N: 'NETWORK', A: 'ADJACENT', L: 'LOCAL', P: 'PHYSICAL' };
  const acMap: Record<string, AttackComplexity> = { L: 'LOW', H: 'HIGH' };
  const prMap: Record<string, PrivilegesRequired> = { N: 'NONE', L: 'LOW', H: 'HIGH' };
  const uiMap: Record<string, UserInteraction> = { N: 'NONE', R: 'REQUIRED' };
  const sMap: Record<string, Scope> = { U: 'UNCHANGED', C: 'CHANGED' };
  const impMap: Record<string, ImpactMetric> = { N: 'NONE', L: 'LOW', H: 'HIGH' };

  return {
    attackVector: avMap[dict['AV'] ?? 'N'] ?? 'NETWORK',
    attackComplexity: acMap[dict['AC'] ?? 'L'] ?? 'LOW',
    privilegesRequired: prMap[dict['PR'] ?? 'N'] ?? 'NONE',
    userInteraction: uiMap[dict['UI'] ?? 'N'] ?? 'NONE',
    scope: sMap[dict['S'] ?? 'U'] ?? 'UNCHANGED',
    confidentiality: impMap[dict['C'] ?? 'N'] ?? 'NONE',
    integrity: impMap[dict['I'] ?? 'N'] ?? 'NONE',
    availability: impMap[dict['A'] ?? 'N'] ?? 'NONE',
  };
}
