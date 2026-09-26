const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export const AUTH_TOKEN_KEY = 'securityscan_auth_token';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

const ERROR_MESSAGES: Record<number, string> = {
  400: 'Bad request. Please verify the input values.',
  401: 'Session expired or authentication is required. Please authenticate again.',
  403: 'Access denied. Insufficient permissions or target not authorized.',
  404: 'Requested resource was not found.',
  409: 'Conflict. An identical resource already exists.',
  422: 'Validation error. Please check the submitted fields.',
  429: 'Rate limit reached. Please wait a moment before trying again.',
  500: 'Internal server error occurred.',
  503: 'Service temporarily unavailable. Please retry later.',
};

let inMemoryToken: string | null = null;

export function getAuthToken(): string | null {
  if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined') {
    try {
      return localStorage.getItem(AUTH_TOKEN_KEY);
    } catch {
      return inMemoryToken;
    }
  }
  return inMemoryToken;
}

export function setAuthToken(token: string | null): void {
  inMemoryToken = token;
  if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined') {
    try {
      if (token) {
        localStorage.setItem(AUTH_TOKEN_KEY, token);
      } else {
        localStorage.removeItem(AUTH_TOKEN_KEY);
      }
    } catch {
      // ignore storage quota / sandbox errors
    }
  }
}

export function clearAuthToken(): void {
  setAuthToken(null);
}

export async function fetchApi<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (options?.headers) {
    Object.assign(headers, options.headers);
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorPayload: { code?: string; message?: string; details?: unknown } | undefined;
    try {
      const parsed = (await res.json()) as { error?: { code?: string; message?: string; details?: unknown } };
      errorPayload = parsed?.error;
    } catch {
      // ignore JSON parse failure on non-JSON response
    }

    if (res.status === 401) {
      clearAuthToken();
    }

    const code = errorPayload?.code || `HTTP_${res.status}`;
    const serverMessage = errorPayload?.message;
    const defaultMsg = ERROR_MESSAGES[res.status] || `API Error: ${res.status} ${res.statusText}`;
    const userMessage = serverMessage ? `${defaultMsg} (${serverMessage})` : defaultMsg;

    throw new ApiError(res.status, code, userMessage, errorPayload?.details);
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
  endpointsDiscovered?: number;
  findingsFound?: number;
  findingsTotal?: number;
  findingsConfirmed?: number;
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
  projectId?: string;
  targetId?: string;
  targetUrl?: string;
  scopePatterns?: string[];
  profile?: string;
  dryRun?: boolean;
  authProfileIds?: string[];
  enabledCategories?: string[];
  excludedChecks?: string[];
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
  getEventsUrl: (id: string) => {
    const token = getAuthToken();
    return token
      ? `${API_BASE}/api/scans/${id}/events?token=${encodeURIComponent(token)}`
      : `${API_BASE}/api/scans/${id}/events`;
  },
};

export interface ApiTargetChallenge {
  token: string;
  method?: string;
  wellKnownPath: string;
  expectedContent: string;
  dnsRecordName: string;
  dnsExpectedValue: string;
  expiresAt: string;
}

export interface CreateTargetRequest {
  projectId: string;
  baseUrl: string;
  name?: string;
}

// Targets
export const targetsApi = {
  list: (projectId?: string) =>
    fetchApi<ApiTarget[]>(projectId ? `/api/targets?projectId=${projectId}` : '/api/targets'),
  get: (id: string) => fetchApi<ApiTarget>(`/api/targets/${id}`),
  create: (data: CreateTargetRequest) =>
    fetchApi<ApiTarget>('/api/targets', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  initiateVerification: (id: string, method?: string) =>
    fetchApi<{ targetId: string; challenge: ApiTargetChallenge }>(`/api/targets/${id}/verify/initiate`, {
      method: 'POST',
      body: JSON.stringify({ method }),
    }),
  checkVerification: (id: string, method?: string) =>
    fetchApi<{ verified: boolean; target: ApiTarget; result: { verified: boolean; method: string; details?: string } }>(
      `/api/targets/${id}/verify/check`,
      {
        method: 'POST',
        body: JSON.stringify({ method }),
      },
    ),
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

export interface ApiUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface AuthResponse {
  user: ApiUser;
  token: string;
}

// Authentication
export const authApi = {
  login: async (email: string, password: string): Promise<AuthResponse> => {
    const data = await fetchApi<AuthResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    setAuthToken(data.token);
    return data;
  },
  register: async (email: string, name: string, password: string): Promise<AuthResponse> => {
    const data = await fetchApi<AuthResponse>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, name, password }),
    });
    setAuthToken(data.token);
    return data;
  },
  logout: () => {
    clearAuthToken();
  },
  ensureSession: async (): Promise<string | null> => {
    const existing = getAuthToken();
    if (existing) return existing;
    try {
      const res = await authApi.login('admin@securityscan.dev', 'Admin123!');
      return res.token;
    } catch {
      return null;
    }
  },
};

