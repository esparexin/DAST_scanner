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

  return res.json();
}

// ---- Typed API client functions ----

export interface ApiScan {
  _id: string;
  targetUrl: string;
  profile: string;
  status: string;
  findingsCount?: number;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
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

export interface ApiReport {
  _id: string;
  scanId: string;
  format: string;
  status: string;
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
  scopePatterns: string[];
  profile: string;
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
  generate: (scanId: string, format: string) =>
    fetchApi<ApiReport>('/api/reports', {
      method: 'POST',
      body: JSON.stringify({ scanId, format }),
    }),
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
