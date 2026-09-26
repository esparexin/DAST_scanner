'use client';

import { useState, useEffect, useCallback } from 'react';
import { Nav } from '@/components/nav';
import { VerifyTargetModal } from '@/components/verify-target-modal';
import { targetsApi, projectsApi, type ApiTarget, type ApiProject } from '@/lib/api';
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
      const created = await targetsApi.create({
        projectId: newProjectId,
        baseUrl: newBaseUrl.trim(),
        name: newTargetName.trim() || undefined,
      });
      setTargets((prev) => [created, ...prev]);
      setShowAddModal(false);
      setNewBaseUrl('');
      setNewTargetName('');
      // Auto-open verification modal for the newly added target
      setSelectedTarget(created);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to add target';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  }

  const authorizedCount = targets.filter((t) => t.authorization === 'AUTHORIZED').length;
  const pendingCount = targets.filter((t) => t.authorization !== 'AUTHORIZED').length;

  return (
    <>
      <Nav />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tight">Security Targets</h1>
            <p className="text-sm text-gray-400 mt-1">
              Manage target domains and verify ownership via DNS TXT or HTTP well-known challenges
            </p>
          </div>
          <button
            onClick={() => setShowAddModal(true)}
            className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors shadow-sm"
          >
            + Add Target
          </button>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl shadow-sm">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              Total Targets
            </span>
            <p className="text-3xl font-bold text-white mt-1">{targets.length}</p>
          </div>
          <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl shadow-sm">
            <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
              Authorized
            </span>
            <p className="text-3xl font-bold text-emerald-400 mt-1">{authorizedCount}</p>
            <span className="text-[11px] text-gray-500">Ready for full active scanning</span>
          </div>
          <div className="bg-gray-900 border border-gray-800 p-5 rounded-xl shadow-sm">
            <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">
              Pending Verification
            </span>
            <p className="text-3xl font-bold text-amber-400 mt-1">{pendingCount}</p>
            <span className="text-[11px] text-gray-500">Ownership challenge required</span>
          </div>
        </div>

        {/* Targets Table */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden shadow-xl">
          <div className="px-6 py-4 border-b border-gray-800 flex justify-between items-center">
            <h2 className="text-base font-semibold text-white">Target Inventory</h2>
            <span className="text-xs text-gray-400">{targets.length} targets configured</span>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-800 text-left">
              <thead className="bg-gray-950/60 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                <tr>
                  <th className="px-6 py-3.5">Target</th>
                  <th className="px-6 py-3.5">Project</th>
                  <th className="px-6 py-3.5">Authorization</th>
                  <th className="px-6 py-3.5">Created</th>
                  <th className="px-6 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 text-sm">
                {loading ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center text-gray-500">
                      Loading target inventory...
                    </td>
                  </tr>
                ) : targets.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center text-gray-500">
                      No targets added yet. Click &quot;Add Target&quot; to configure your first domain.
                    </td>
                  </tr>
                ) : (
                  targets.map((target) => {
                    const isAuth = target.authorization === 'AUTHORIZED';
                    const projectName =
                      projects.find((p) => p._id === target.projectId)?.name || target.projectId;

                    return (
                      <tr key={target._id} className="hover:bg-gray-800/40 transition-colors">
                        <td className="px-6 py-4 font-mono font-medium text-white">
                          <div>
                            {target.name && (
                              <div className="font-sans text-xs text-gray-400 mb-0.5">{target.name}</div>
                            )}
                            <span className="text-indigo-400">{target.baseUrl}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-gray-400 text-xs truncate max-w-xs">
                          {projectName}
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                              isAuth
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            }`}
                          >
                            <span
                              className={`h-1.5 w-1.5 rounded-full ${
                                isAuth ? 'bg-emerald-400' : 'bg-amber-400'
                              }`}
                            />
                            {target.authorization}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-xs text-gray-400">
                          {new Date(target.createdAt).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex justify-end items-center gap-2">
                            <button
                              onClick={() => setSelectedTarget(target)}
                              className={`text-xs font-semibold px-3 py-1.5 rounded-lg border transition-colors ${
                                isAuth
                                  ? 'border-gray-700 text-gray-300 hover:bg-gray-800'
                                  : 'border-indigo-500/60 bg-indigo-950/40 text-indigo-300 hover:bg-indigo-900/60'
                              }`}
                            >
                              {isAuth ? 'View Challenge' : 'Verify Ownership'}
                            </button>
                            {isAuth && (
                              <Link
                                href={`/scans`}
                                className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 hover:bg-emerald-900/60 transition-colors"
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
          <div className="fixed inset-0 z-50 overflow-y-auto bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-md w-full p-6 shadow-2xl text-gray-100">
              <div className="flex justify-between items-center pb-3 border-b border-gray-800 mb-4">
                <h3 className="text-lg font-bold text-white">Add Security Target</h3>
                <button
                  onClick={() => setShowAddModal(false)}
                  className="text-gray-400 hover:text-white p-1 rounded-md"
                >
                  ✕
                </button>
              </div>

              {error && (
                <div className="p-3 bg-red-950/80 border border-red-800 rounded-lg text-red-200 text-xs mb-4">
                  {error}
                </div>
              )}

              <form onSubmit={handleAddTarget} className="space-y-4 text-sm">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Target Base URL *
                  </label>
                  <input
                    type="url"
                    required
                    placeholder="https://example.com"
                    value={newBaseUrl}
                    onChange={(e) => setNewBaseUrl(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 text-xs font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Display Name (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="Production Web Portal"
                    value={newTargetName}
                    onChange={(e) => setNewTargetName(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 text-xs"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Project *
                  </label>
                  <select
                    value={newProjectId}
                    onChange={(e) => setNewProjectId(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-indigo-500 text-xs"
                  >
                    {projects.map((p) => (
                      <option key={p._id} value={p._id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="flex justify-end gap-3 pt-3 border-t border-gray-800">
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-xs font-semibold transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="bg-indigo-600 hover:bg-indigo-500 text-white px-5 py-2 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
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
      </main>
    </>
  );
}
