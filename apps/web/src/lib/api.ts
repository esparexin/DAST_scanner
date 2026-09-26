const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export async function fetchApi<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!res.ok) {
    throw new Error(`API Error: ${res.status} ${res.statusText}`);
  }

  const json = await res.json();
  if (json && typeof json === 'object' && 'data' in json) {
    return json.data as T;
  }
  return json as T;
}

// ---- Typed API client functions ----

export interface ApiScanProgress {
  phase?: string;
  percent?: number;
  currentTask?: string;
  totalEndpoints?: number;
  testedEndpoints?: number;
  findingsFound?: number;
}

export interface ApiScan {
  _id: string;
  projectId?: string;
  targetId?: string;
  targetUrl: string;
  profile: string;
  status: string;
  dryRun?: boolean;
  findingsCount?: number;
  progress?: ApiScanProgress;
  startedAt?: string;
  completedAt?: string;
  cancelledAt?: string;
  createdAt: string;
}

export interface ApiDryRunResult {
  target: string;
  allowedHosts: string[];
  excludedHosts: string[];
  allowedPaths: string[];
  excludedPaths: string[];
  scanProfile: string;
  authProfileCount: number;
  enabledCategories: string[];
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  maxRequests: number;
  maxCrawlDepth: number;
  maxScanDuration: number;
  dryRun: boolean;
}

export interface ApiFinding {
  _id: string;
  scanId: string;
  ruleId: string;
  title: string;
  severity: string;
  confidence: string;
  category: string;
  endpoint: string;
  method: string;
  parameter?: string;
  status: string;
  cwe?: string[];
  owasp?: string[];
  createdAt: string;
}

export interface ApiProject {
  _id: string;
  name: string;
  description?: string;
  targets: string[];
  createdAt: string;
}

export interface ApiTarget {
  _id: string;
  projectId: string;
  baseUrl: string;
  name?: string;
  authorization: string;
  createdAt: string;
}

export interface ApiReport {
  _id: string;
  scanId: string;
  projectId?: string;
  targetId?: string;
  format: string;
  title: string;
  generatedAt?: string;
  scope?: {
    targetUrl?: string;
    scanProfile?: string;
  };
  summary?: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    confirmedCount?: number;
    endpointsScanned?: number;
    requestsMade?: number;
  };
  storageKey?: string;
  storageUrl?: string;
  status?: string;
  createdAt: string;
}

export interface ApiAuditLog {
  id?: string;
  _id?: string;
  userId: string;
  action: string;
  resource: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress: string;
  timestamp: string;
}

export interface ApiStats {
  activeScans: number;
  totalProjects: number;
  openFindings: number;
  totalReports: number;
}

export interface CreateScanRequest {
  targetUrl: string;
  scopePatterns?: string[];
  profile: string;
  dryRun?: boolean;
}

// Scans
export const scansApi = {
  list: () => fetchApi<ApiScan[]>('/api/scans'),
  get: (id: string) => fetchApi<ApiScan>(`/api/scans/${id}`),
  create: (data: CreateScanRequest) =>
    fetchApi<ApiScan>('/api/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  cancel: (id: string) =>
    fetchApi<ApiScan>(`/api/scans/${id}/cancel`, { method: 'POST' }),
  dryRun: (id: string) =>
    fetchApi<ApiDryRunResult>(`/api/scans/${id}/dry-run`, { method: 'POST' }),
  getEventsUrl: (id: string) => `${API_BASE}/api/scans/${id}/events`,
};

// Targets
export const targetsApi = {
  list: (projectId?: string) =>
    fetchApi<ApiTarget[]>(projectId ? `/api/targets?projectId=${projectId}` : '/api/targets'),
  get: (id: string) => fetchApi<ApiTarget>(`/api/targets/${id}`),
};

// Findings
export const findingsApi = {
  list: (scanId?: string) =>
    fetchApi<ApiFinding[]>(scanId ? `/api/findings?scanId=${scanId}` : '/api/findings'),
  get: (id: string) => fetchApi<ApiFinding>(`/api/findings/${id}`),
  updateStatus: (id: string, status: string) =>
    fetchApi<ApiFinding>(`/api/findings/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
};

// Projects
export const projectsApi = {
  list: () => fetchApi<ApiProject[]>('/api/projects'),
  get: (id: string) => fetchApi<ApiProject>(`/api/projects/${id}`),
  create: (data: { name: string; description?: string }) =>
    fetchApi<ApiProject>('/api/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
};

// Reports
export const reportsApi = {
  list: () => fetchApi<ApiReport[]>('/api/reports'),
  get: (id: string) => fetchApi<ApiReport>(`/api/reports/${id}`),
  generate: (scanId: string, format: string) =>
    fetchApi<ApiReport>('/api/reports', {
      method: 'POST',
      body: JSON.stringify({ scanId, format }),
    }),
  getDownloadUrl: (id: string) => `${API_BASE}/api/reports/${id}/download`,
};

// Audit Logs
export const auditApi = {
  list: (action?: string) =>
    fetchApi<ApiAuditLog[]>(action ? `/api/audit?action=${action}` : '/api/audit'),
};

// Dashboard stats
export const statsApi = {
  get: () => fetchApi<ApiStats>('/api/health/stats'),
};
