'use client';

import Link from 'next/link';
import { useEffect, useState, useCallback, useMemo } from 'react';
import { StatusBadge } from '../../components/status-badge';
import { ScanProgressModal } from '../../components/scan-progress-modal';
import { ScanProfile, ScanStatus } from '@securityscan/contracts';
import {
  scansApi,
  targetsApi,
  authApi,
  type ApiScan,
  type ApiTarget,
  type ApiDryRunResult,
  type CreateScanRequest,
} from '../../lib/api';

/** Derived from the ScanProfile enum in @securityscan/contracts — no magic strings */
const SCAN_PROFILES = Object.values(ScanProfile);

/** Statuses where a scan can no longer transition to another state */
const TERMINAL_STATUSES = new Set<string>([
  ScanStatus.COMPLETED,
  ScanStatus.FAILED,
  ScanStatus.CANCELLED,
  ScanStatus.TIMEOUT,
]);

export default function ScansPage() {
  const [scans, setScans] = useState<ApiScan[]>([]);
  const [targets, setTargets] = useState<ApiTarget[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [newProfile, setNewProfile] = useState('WEB_STANDARD');
  const [newDryRun, setNewDryRun] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [dryRunModal, setDryRunModal] = useState<{ scanId: string; data: ApiDryRunResult } | null>(null);
  const [dryRunLoading, setDryRunLoading] = useState<string | null>(null);
  const [selectedScanForDetails, setSelectedScanForDetails] = useState<ApiScan | null>(null);

  useEffect(() => {
    if (!selectedScanForDetails) return;
    const match = scans.find((s) => s._id === selectedScanForDetails._id);
    if (match) setSelectedScanForDetails(match);
  }, [scans, selectedScanForDetails?._id]);

  const loadData = useCallback(async () => {
    try {
      await authApi.ensureSession();
      const [scansData, targetsData] = await Promise.all([
        scansApi.list().catch(() => []),
        targetsApi.list().catch(() => []),
      ]);
      setScans(scansData);
      setTargets(targetsData);
      if (targetsData.length > 0 && targetsData[0]?._id) {
        const firstId = targetsData[0]._id;
        setSelectedTargetId((current) => current || firstId);
      }
    } catch {
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [loadData]);

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
            const phase = payload.phase || payload.progress?.phase;
            const msg = payload.message || payload.progress?.currentTask;
            setScans((currentScans) =>
              currentScans.map((s) => {
                if (s._id === payload.scanId) {
                  return {
                    ...s,
                    status: phase || s.status,
                    findingsCount: payload.findingsTotal ?? s.findingsCount,
                    progress: {
                      ...s.progress,
                      phase: phase || s.progress?.phase,
                      percent: payload.progress?.percent ?? s.progress?.percent,
                      currentTask: msg || s.progress?.currentTask,
                      endpointsDiscovered: payload.endpointsDiscovered ?? s.progress?.endpointsDiscovered,
                      findingsTotal: payload.findingsTotal ?? s.progress?.findingsTotal,
                    },
                  };
                }
                return s;
              }),
            );

            if (phase && TERMINAL_STATUSES.has(phase)) {
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

  const selectedTarget = useMemo(() => {
    return targets.find((t) => t._id === selectedTargetId) || null;
  }, [targets, selectedTargetId]);

  const handleCreate = async () => {
    if (!selectedTarget) {
      setError('Please select a target for this scan.');
      return;
    }
    if (selectedTarget.authorization !== 'AUTHORIZED' && !newDryRun) {
      setError('Target ownership is not verified. Complete verification under Targets or run in Dry-Run Mode.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const payload: CreateScanRequest = {
        projectId: selectedTarget.projectId,
        targetId: selectedTarget._id,
        profile: newProfile,
        dryRun: newDryRun,
      };
      await scansApi.create(payload);
      setShowNew(false);
      setNewDryRun(false);
      await loadData();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create scan';
      setError(msg);
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
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to cancel scan';
      setError(msg);
    } finally {
      setCancellingId(null);
    }
  };

  const handleInspectDryRun = async (id: string) => {
    setDryRunLoading(id);
    try {
      const data = await scansApi.dryRun(id);
      setDryRunModal({ scanId: id, data });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to inspect scan configuration';
      setError(msg);
    } finally {
      setDryRunLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-black">Scans</h1>
          <p className="mt-1 text-sm text-gray-700">
            Manage and monitor security scans with live progress streaming
          </p>
        </div>
        <button
          onClick={() => setShowNew(true)}
          className="bg-black text-white px-4 py-2 rounded-lg hover:bg-gray-800 transition-colors text-sm font-bold shadow-sm"
        >
          + New Scan
        </button>
      </div>

      {showNew && (
        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
          <h3 className="text-lg font-bold text-black mb-4">Create New Scan</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-bold text-black mb-1">
                Target
              </label>
              {targets.length === 0 ? (
                <div className="text-sm text-gray-700 bg-gray-50 border border-gray-300 rounded-lg p-3 font-medium">
                  No targets found.{' '}
                  <Link href="/targets" className="text-black font-bold underline">
                    Add and verify a target in Targets first
                  </Link>
                </div>
              ) : (
                <select
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm text-black focus:ring-1 focus:ring-black focus:border-black"
                >
                  {targets.map((t) => (
                    <option key={t._id} value={t._id}>
                      {t.name ? `${t.name} (${t.baseUrl})` : t.baseUrl}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div>
              <label className="block text-sm font-bold text-black mb-1">
                Scan Profile
              </label>
              <select
                value={newProfile}
                onChange={(e) => setNewProfile(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm text-black focus:ring-1 focus:ring-black focus:border-black"
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
              className="h-4 w-4 text-black focus:ring-black border-gray-300 rounded"
            />
            <label htmlFor="dryRun" className="ml-2 block text-sm font-medium text-black">
              Run in Dry-Run Mode (validates scope and configurations without executing active attack payloads)
            </label>
          </div>
          {error && <p className="mt-2 text-sm text-red-600 font-semibold">{error}</p>}
          <div className="mt-4 flex gap-3">
            <button
              onClick={handleCreate}
              disabled={submitting || targets.length === 0}
              className="bg-black text-white px-5 py-2 rounded-lg hover:bg-gray-800 disabled:opacity-50 text-xs font-bold transition-colors shadow-sm"
            >
              {submitting ? 'Creating...' : 'Start Scan'}
            </button>
            <button
              onClick={() => setShowNew(false)}
              className="bg-gray-100 text-black px-4 py-2 rounded-lg hover:bg-gray-200 text-xs font-bold transition-colors"
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

      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Target
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Profile
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Status & Progress
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Findings
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Created
              </th>
              <th className="px-6 py-3.5 text-right text-xs font-bold text-black uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-sm text-gray-600 font-medium">
                  Loading scans...
                </td>
              </tr>
            ) : scans.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-sm text-gray-600 font-medium">
                  No scans yet. Click "New Scan" to get started.
                </td>
              </tr>
            ) : (
              scans.map((scan) => {
                const isActive = !TERMINAL_STATUSES.has(scan.status);
                const percent = scan.progress?.percent ?? 0;
                return (
                  <tr key={scan._id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-bold text-black">
                      {scan.targetUrl}
                      {scan.dryRun && (
                        <span className="ml-2 inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-900 border border-amber-300">
                          DRY RUN
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-800">
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
                                className="bg-black h-1.5 rounded-full transition-all duration-300"
                                style={{ width: `${Math.min(100, Math.max(5, percent))}%` }}
                              />
                            </div>
                            {scan.progress?.currentTask && (
                              <p className="text-[11px] text-gray-700 truncate mt-0.5 font-medium">
                                {scan.progress.currentTask}
                              </p>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-bold text-black">
                      {scan.findingsCount ?? 0}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-800">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex justify-end items-center gap-2">
                        <button
                          onClick={() => setSelectedScanForDetails(scan)}
                          className="text-black hover:bg-gray-100 text-xs font-bold px-2.5 py-1.5 rounded-lg border border-gray-300 transition-colors flex items-center gap-1.5"
                        >
                          {isActive && (
                            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                          )}
                          {isActive ? 'Live Progress' : 'Details'}
                        </button>
                        {isActive && (
                          <button
                            onClick={() => handleCancel(scan._id)}
                            disabled={cancellingId === scan._id}
                            className="text-red-700 hover:bg-red-50 text-xs font-bold px-2.5 py-1.5 rounded-lg border border-red-300 disabled:opacity-50 transition-colors"
                          >
                            {cancellingId === scan._id ? 'Cancelling...' : 'Cancel'}
                          </button>
                        )}
                        <button
                          onClick={() => handleInspectDryRun(scan._id)}
                          disabled={dryRunLoading === scan._id}
                          className="text-black hover:bg-gray-100 text-xs font-bold px-2.5 py-1.5 rounded-lg border border-gray-300 disabled:opacity-50 transition-colors"
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

      <ScanProgressModal
        scan={selectedScanForDetails}
        isOpen={!!selectedScanForDetails}
        onClose={() => setSelectedScanForDetails(null)}
        onCancel={handleCancel}
      />
    </div>
  );
}
