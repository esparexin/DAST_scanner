'use client';

import { useState, useEffect, useCallback } from 'react';
import { VerifyTargetModal } from '@/components/verify-target-modal';
import { targetsApi, projectsApi, authApi, ApiError, type ApiTarget, type ApiProject } from '@/lib/api';
import Link from 'next/link';

export default function TargetsPage() {
  const [targets, setTargets] = useState<ApiTarget[]>([]);
  const [projects, setProjects] = useState<ApiProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTarget, setSelectedTarget] = useState<ApiTarget | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newBaseUrl, setNewBaseUrl] = useState('');
  const [newTargetName, setNewTargetName] = useState('');
  const [newProjectId, setNewProjectId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      await authApi.ensureSession();
      const [targetsData, projectsData] = await Promise.all([
        targetsApi.list().catch(() => []),
        projectsApi.list().catch(() => []),
      ]);
      setTargets(targetsData);
      setProjects(projectsData);
      if (projectsData[0]?._id) {
        setNewProjectId(projectsData[0]._id);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  async function handleAddTarget(e: React.FormEvent) {
    e.preventDefault();
    if (!newBaseUrl.trim() || !newProjectId) return;
    try {
      setSubmitting(true);
      setError(null);

      // Normalize URL (prepend https:// if protocol is omitted)
      let formattedUrl = newBaseUrl.trim();
      if (!/^https?:\/\//i.test(formattedUrl)) {
        formattedUrl = `https://${formattedUrl}`;
      }

      // Parse hostname for scope and fallback target name
      let hostname: string;
      try {
        const parsed = new URL(formattedUrl);
        hostname = parsed.hostname;
        if (!hostname) {
          throw new Error('Invalid host');
        }
      } catch {
        setError('Please enter a valid URL (e.g. https://example.com or example.com)');
        setSubmitting(false);
        return;
      }

      const targetName = newTargetName.trim() || hostname;

      const created = await targetsApi.create({
        projectId: newProjectId,
        baseUrl: formattedUrl,
        name: targetName,
        scope: {
          allowedHosts: [hostname],
        },
      });
      setTargets((prev) => [created, ...prev]);
      setShowAddModal(false);
      setNewBaseUrl('');
      setNewTargetName('');
      // Auto-open verification modal for the newly added target
      setSelectedTarget(created);
    } catch (err: unknown) {
      if (err instanceof ApiError && Array.isArray(err.details)) {
        const detailMsgs = err.details
          .map((d: { message?: string }) => d.message)
          .filter(Boolean);
        setError(detailMsgs.length > 0 ? detailMsgs.join('. ') : err.message);
      } else {
        const msg = err instanceof Error ? err.message : 'Failed to add target';
        setError(msg);
      }
    } finally {
      setSubmitting(false);
    }
  }

  const authorizedCount = targets.filter((t) => t.authorization === 'AUTHORIZED').length;
  const pendingCount = targets.filter((t) => t.authorization !== 'AUTHORIZED').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-black tracking-tight">Security Targets</h1>
          <p className="text-sm text-gray-700 mt-1">
            Manage target domains and verify ownership via DNS TXT or HTTP well-known challenges
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="bg-black hover:bg-gray-800 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors shadow-sm"
        >
          + Add Target
        </button>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white border border-gray-200 p-5 rounded-xl shadow-sm">
          <span className="text-xs font-bold text-black uppercase tracking-wider">
            Total Targets
          </span>
          <p className="text-3xl font-bold text-black mt-1">{targets.length}</p>
        </div>
        <div className="bg-white border border-gray-200 p-5 rounded-xl shadow-sm">
          <span className="text-xs font-bold text-emerald-700 uppercase tracking-wider">
            Authorized
          </span>
          <p className="text-3xl font-bold text-black mt-1">{authorizedCount}</p>
          <span className="text-[11px] text-gray-700">Ready for full active scanning</span>
        </div>
        <div className="bg-white border border-gray-200 p-5 rounded-xl shadow-sm">
          <span className="text-xs font-bold text-amber-700 uppercase tracking-wider">
            Pending Verification
          </span>
          <p className="text-3xl font-bold text-black mt-1">{pendingCount}</p>
          <span className="text-[11px] text-gray-700">Ownership challenge required</span>
        </div>
      </div>

      {/* Targets Table */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
          <h2 className="text-base font-bold text-black">Target Inventory</h2>
          <span className="text-xs font-semibold text-gray-700">{targets.length} targets configured</span>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 text-left">
            <thead className="bg-gray-50 text-xs font-bold text-black uppercase tracking-wider">
              <tr>
                <th className="px-6 py-3.5">Target</th>
                <th className="px-6 py-3.5">Project</th>
                <th className="px-6 py-3.5">Authorization</th>
                <th className="px-6 py-3.5">Created</th>
                <th className="px-6 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 text-sm bg-white">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-gray-600 font-medium">
                    Loading target inventory...
                  </td>
                </tr>
              ) : targets.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-gray-600 font-medium">
                    No targets added yet. Click &quot;Add Target&quot; to configure your first domain.
                  </td>
                </tr>
              ) : (
                targets.map((target) => {
                  const isAuth = target.authorization === 'AUTHORIZED';
                  const projectName =
                    projects.find((p) => p._id === target.projectId)?.name || target.projectId;

                  return (
                    <tr key={target._id} className="hover:bg-gray-50 transition-colors">
                      <td className="px-6 py-4 font-mono font-semibold text-black">
                        <div>
                          {target.name && (
                            <div className="font-sans text-xs text-gray-700 mb-0.5">{target.name}</div>
                          )}
                          <span className="text-black font-mono">{target.baseUrl}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-gray-800 text-xs truncate max-w-xs font-medium">
                        {projectName}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold ${
                            isAuth
                              ? 'bg-emerald-50 text-emerald-800 border border-emerald-300'
                              : 'bg-amber-50 text-amber-800 border border-amber-300'
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              isAuth ? 'bg-emerald-600' : 'bg-amber-600'
                            }`}
                          />
                          {target.authorization}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-xs text-gray-800 font-medium">
                        {new Date(target.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex justify-end items-center gap-2">
                          <button
                            onClick={() => setSelectedTarget(target)}
                            className={`text-xs font-bold px-3 py-1.5 rounded-lg border transition-colors ${
                              isAuth
                                ? 'border-gray-300 text-black hover:bg-gray-100'
                                : 'border-black bg-black text-white hover:bg-gray-800'
                            }`}
                          >
                            {isAuth ? 'View Challenge' : 'Verify Ownership'}
                          </button>
                          {isAuth && (
                            <Link
                              href="/scans"
                              className="text-xs font-bold px-3 py-1.5 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-800 hover:bg-emerald-100 transition-colors"
                            >
                              Scan
                            </Link>
                          )}
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

      {/* Add Target Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-gray-200 rounded-xl max-w-md w-full p-6 shadow-2xl text-black">
            <div className="flex justify-between items-center pb-3 border-b border-gray-200 mb-4">
              <h3 className="text-lg font-bold text-black">Add Security Target</h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-black hover:text-gray-700 p-1 rounded-md font-bold"
              >
                ✕
              </button>
            </div>

            {error && (
              <div className="p-3 bg-red-50 border border-red-300 rounded-lg text-red-800 text-xs mb-4">
                {error}
              </div>
            )}

            <form onSubmit={handleAddTarget} className="space-y-4 text-sm">
              <div>
                <label className="block text-xs font-bold text-black mb-1">
                  Target Base URL * <span className="text-[11px] text-gray-500 font-normal">(e.g. https://example.com or example.com)</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="https://example.com"
                  value={newBaseUrl}
                  onChange={(e) => setNewBaseUrl(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg px-3 py-2 text-black placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-black text-xs font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-black mb-1">
                  Display Name (Optional)
                </label>
                <input
                  type="text"
                  placeholder="Production Web Portal"
                  value={newTargetName}
                  onChange={(e) => setNewTargetName(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg px-3 py-2 text-black placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-black text-xs"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-black mb-1">
                  Project *
                </label>
                <select
                  value={newProjectId}
                  onChange={(e) => setNewProjectId(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg px-3 py-2 text-black focus:outline-none focus:ring-1 focus:ring-black text-xs"
                >
                  {projects.map((p) => (
                    <option key={p._id} value={p._id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-gray-200">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="bg-gray-100 hover:bg-gray-200 text-black px-4 py-2 rounded-lg text-xs font-bold transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="bg-black hover:bg-gray-800 text-white px-5 py-2 rounded-lg text-xs font-bold transition-colors disabled:opacity-50"
                >
                  {submitting ? 'Adding...' : 'Add & Verify'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Target Verification Modal */}
      <VerifyTargetModal
        target={selectedTarget}
        isOpen={!!selectedTarget}
        onClose={() => setSelectedTarget(null)}
        onVerified={(updatedTarget) => {
          setTargets((prev) =>
            prev.map((t) => (t._id === updatedTarget._id ? updatedTarget : t)),
          );
          setSelectedTarget(updatedTarget);
        }}
      />
    </div>
  );
}
