'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { StatusBadge } from '../../components/status-badge';
import {
  scansApi,
  type ApiScan,
  type ApiDryRunResult,
  type CreateScanRequest,
} from '../../lib/api';

const SCAN_PROFILES = [
  'PASSIVE',
  'QUICK',
  'WEB_STANDARD',
  'API_STANDARD',
  'AUTHENTICATED',
  'AUTHORIZATION',
  'FULL_ASSESSMENT',
  'CICD',
  'PRODUCTION_SAFE',
  'SECURITY_LAB',
];

const TERMINAL_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT']);

export default function ScansPage() {
  const [scans, setScans] = useState<ApiScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [newTarget, setNewTarget] = useState('');
  const [newProfile, setNewProfile] = useState('WEB_STANDARD');
  const [newDryRun, setNewDryRun] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [dryRunModal, setDryRunModal] = useState<{ scanId: string; data: ApiDryRunResult } | null>(null);
  const [dryRunLoading, setDryRunLoading] = useState<string | null>(null);

  const loadScans = useCallback(async () => {
    try {
      const data = await scansApi.list();
      setScans(data);
    } catch {
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 10000);
    return () => clearInterval(interval);
  }, [loadScans]);

  // Hook real-time Server-Sent Events (SSE) for active, in-progress scans
  const activeScanIdsKey = useMemo(() => {
    return scans
      .filter((s) => !TERMINAL_STATUSES.has(s.status))
      .map((s) => `${s._id}:${s.status}`)
      .join(',');
  }, [scans]);

  useEffect(() => {
    const activeScans = scans.filter((s) => !TERMINAL_STATUSES.has(s.status));
    if (activeScans.length === 0) return;

    const eventSources: EventSource[] = [];

    for (const scan of activeScans) {
      try {
        const es = new EventSource(scansApi.getEventsUrl(scan._id));

        es.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            setScans((currentScans) =>
              currentScans.map((s) => {
                if (s._id === payload.scanId) {
                  return {
                    ...s,
                    status: payload.phase || s.status,
                    progress: payload.progress ?? s.progress,
                  };
                }
                return s;
              }),
            );

            if (payload.phase && TERMINAL_STATUSES.has(payload.phase)) {
              es.close();
            }
          } catch {
            // ignore non-json SSE frames
          }
        };

        es.onerror = () => {
          es.close();
        };

        eventSources.push(es);
      } catch {
        // SSE not supported or connection error
      }
    }

    return () => {
      for (const es of eventSources) {
        es.close();
      }
    };
  }, [activeScanIdsKey]);

  const handleCreate = async () => {
    if (!newTarget.trim()) return;
    setSubmitting(true);
    setError('');
    try {
      const payload: CreateScanRequest = {
        targetUrl: newTarget.trim(),
        scopePatterns: [`${new URL(newTarget.trim()).origin}/*`],
        profile: newProfile,
        dryRun: newDryRun,
      };
      await scansApi.create(payload);
      setShowNew(false);
      setNewTarget('');
      setNewDryRun(false);
      await loadScans();
    } catch (err: any) {
      setError(err.message || 'Failed to create scan');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = async (id: string) => {
    setCancellingId(id);
    try {
      const updated = await scansApi.cancel(id);
      setScans((current) =>
        current.map((s) => (s._id === id ? { ...s, status: updated.status, cancelledAt: updated.cancelledAt } : s)),
      );
    } catch (err: any) {
      setError(err.message || 'Failed to cancel scan');
    } finally {
      setCancellingId(null);
    }
  };

  const handleInspectDryRun = async (id: string) => {
    setDryRunLoading(id);
    try {
      const data = await scansApi.dryRun(id);
      setDryRunModal({ scanId: id, data });
    } catch (err: any) {
      setError(err.message || 'Failed to inspect scan configuration');
    } finally {
      setDryRunLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Scans</h1>
          <p className="mt-1 text-gray-600">
            Manage and monitor security scans with live progress streaming
          </p>
        </div>
        <button
          onClick={() => setShowNew(true)}
          className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 transition-colors"
        >
          New Scan
        </button>
      </div>

      {showNew && (
        <div className="bg-white rounded-lg shadow p-6 border-l-4 border-indigo-600">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New Scan</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Target URL
              </label>
              <input
                type="url"
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
                placeholder="https://api.example.com"
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Scan Profile
              </label>
              <select
                value={newProfile}
                onChange={(e) => setNewProfile(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:ring-indigo-500 focus:border-indigo-500"
              >
                {SCAN_PROFILES.map((p) => (
                  <option key={p} value={p}>
                    {p.replace(/_/g, ' ')}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="mt-3 flex items-center">
            <input
              id="dryRun"
              type="checkbox"
              checked={newDryRun}
              onChange={(e) => setNewDryRun(e.target.checked)}
              className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
            />
            <label htmlFor="dryRun" className="ml-2 block text-sm text-gray-700">
              Run in Dry-Run Mode (validates scope and configurations without executing active attack payloads)
            </label>
          </div>
          {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
          <div className="mt-4 flex gap-3">
            <button
              onClick={handleCreate}
              disabled={submitting}
              className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50 text-sm"
            >
              {submitting ? 'Creating...' : 'Start Scan'}
            </button>
            <button
              onClick={() => setShowNew(false)}
              className="bg-gray-100 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-200 text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {dryRunModal && (
        <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl max-w-xl w-full p-6 space-y-4">
            <div className="flex justify-between items-center border-b pb-3">
              <h3 className="text-lg font-semibold text-gray-900">
                Scan Configuration & Scope Inspection
              </h3>
              <button
                onClick={() => setDryRunModal(null)}
                className="text-gray-400 hover:text-gray-600 text-sm font-semibold"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3 text-sm">
              <div>
                <span className="font-semibold text-gray-700">Target Base URL:</span>
                <p className="text-gray-900 font-mono text-xs mt-0.5">{dryRunModal.data.target}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="font-semibold text-gray-700">Scan Profile:</span>
                  <p className="text-gray-900">{dryRunModal.data.scanProfile}</p>
                </div>
                <div>
                  <span className="font-semibold text-gray-700">Mode:</span>
                  <p className="text-gray-900 font-medium">
                    {dryRunModal.data.dryRun ? 'Dry-Run Simulation' : 'Active Execution'}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="font-semibold text-gray-700">Allowed Hosts:</span>
                  <p className="text-gray-900 font-mono text-xs">
                    {dryRunModal.data.allowedHosts?.join(', ') || 'None'}
                  </p>
                </div>
                <div>
                  <span className="font-semibold text-gray-700">Excluded Hosts:</span>
                  <p className="text-gray-900 font-mono text-xs">
                    {dryRunModal.data.excludedHosts?.join(', ') || 'None'}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="font-semibold text-gray-700">Rate Limits:</span>
                  <p className="text-gray-900">
                    {dryRunModal.data.maxRequestsPerSecond} req/s, concurrency {dryRunModal.data.maxConcurrency}
                  </p>
                </div>
                <div>
                  <span className="font-semibold text-gray-700">Max Duration:</span>
                  <p className="text-gray-900">{dryRunModal.data.maxScanDuration} seconds</p>
                </div>
              </div>
            </div>
            <div className="flex justify-end pt-3 border-t">
              <button
                onClick={() => setDryRunModal(null)}
                className="bg-gray-100 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-200 text-sm font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Target
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Profile
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Status & Progress
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Findings
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Created
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-sm text-gray-500">
                  Loading scans...
                </td>
              </tr>
            ) : scans.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-sm text-gray-500">
                  No scans yet. Click "New Scan" to get started.
                </td>
              </tr>
            ) : (
              scans.map((scan) => {
                const isActive = !TERMINAL_STATUSES.has(scan.status);
                const percent = scan.progress?.percent ?? 0;
                return (
                  <tr key={scan._id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {scan.targetUrl}
                      {scan.dryRun && (
                        <span className="ml-2 inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-300">
                          DRY RUN
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.profile}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <StatusBadge status={scan.status} />
                          {isActive && (
                            <span className="inline-flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                          )}
                        </div>
                        {isActive && (
                          <div className="w-36">
                            <div className="w-full bg-gray-200 rounded-full h-1.5">
                              <div
                                className="bg-indigo-600 h-1.5 rounded-full transition-all duration-300"
                                style={{ width: `${Math.min(100, Math.max(5, percent))}%` }}
                              />
                            </div>
                            {scan.progress?.currentTask && (
                              <p className="text-[11px] text-gray-500 truncate mt-0.5">
                                {scan.progress.currentTask}
                              </p>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.findingsCount ?? 0}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex justify-end items-center gap-2">
                        {isActive && (
                          <button
                            onClick={() => handleCancel(scan._id)}
                            disabled={cancellingId === scan._id}
                            className="text-red-600 hover:text-red-800 text-xs font-semibold px-2 py-1 rounded border border-red-200 hover:bg-red-50 disabled:opacity-50 transition-colors"
                          >
                            {cancellingId === scan._id ? 'Cancelling...' : 'Cancel'}
                          </button>
                        )}
                        <button
                          onClick={() => handleInspectDryRun(scan._id)}
                          disabled={dryRunLoading === scan._id}
                          className="text-indigo-600 hover:text-indigo-800 text-xs font-semibold px-2 py-1 rounded border border-indigo-200 hover:bg-indigo-50 disabled:opacity-50 transition-colors"
                        >
                          {dryRunLoading === scan._id ? 'Loading...' : 'Inspect'}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
