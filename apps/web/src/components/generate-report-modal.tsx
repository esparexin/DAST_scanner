'use client';

import { useState } from 'react';
import { reportsApi, type ApiScan } from '@/lib/api';

interface GenerateReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  scans: ApiScan[];
  onSuccess: () => Promise<void> | void;
}

export function GenerateReportModal({
  isOpen,
  onClose,
  scans,
  onSuccess,
}: GenerateReportModalProps) {
  const [selectedScanId, setSelectedScanId] = useState(scans[0]?._id ?? '');
  const [selectedFormat, setSelectedFormat] = useState('JSON');
  const [generating, setGenerating] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    const scanId = selectedScanId || scans[0]?._id;
    if (!scanId) return;
    try {
      setGenerating(true);
      setErrorMessage(null);
      await reportsApi.generate(scanId, selectedFormat);
      onClose();
      await onSuccess();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to generate report';
      setErrorMessage(msg);
    } finally {
      setGenerating(false);
    }
  }

  const effectiveScanId = selectedScanId || scans[0]?._id || '';

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-lg max-w-md w-full p-6 shadow-xl">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold text-gray-100">Generate Compliance Report</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200 text-xl font-bold"
          >
            &times;
          </button>
        </div>

        {errorMessage && (
          <div className="mb-4 p-3 bg-red-950/80 border border-red-800 rounded text-red-200 text-xs">
            {errorMessage}
          </div>
        )}

        <form onSubmit={handleGenerate} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">
              Select Scan
            </label>
            <select
              value={effectiveScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              required
            >
              {scans.length === 0 ? (
                <option value="">No scans available</option>
              ) : (
                scans.map((s) => (
                  <option key={s._id} value={s._id}>
                    {s.targetUrl} - {s.profile} ({s.status})
                  </option>
                ))
              )}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">
              Report Format
            </label>
            <div className="grid grid-cols-3 gap-2">
              {['JSON', 'SARIF', 'HTML'].map((fmt) => (
                <button
                  key={fmt}
                  type="button"
                  onClick={() => setSelectedFormat(fmt)}
                  className={`py-2 px-3 text-xs font-medium rounded border text-center transition ${
                    selectedFormat === fmt
                      ? 'bg-indigo-600 text-white border-indigo-500'
                      : 'bg-gray-800 text-gray-300 border-gray-700 hover:bg-gray-700'
                  }`}
                >
                  {fmt}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-xs text-gray-500">
              {selectedFormat === 'SARIF'
                ? 'OASIS SARIF v2.1.0 format for GitHub Code Scanning and CI/CD pipelines.'
                : selectedFormat === 'HTML'
                  ? 'Self-contained interactive HTML executive summary.'
                  : 'Raw JSON finding structures and technical metadata.'}
            </p>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-300 bg-gray-800 hover:bg-gray-700 rounded-md transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={generating || !effectiveScanId}
              className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-md transition disabled:opacity-50"
            >
              {generating ? 'Generating...' : 'Generate & Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
