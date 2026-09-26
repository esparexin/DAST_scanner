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
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white border border-gray-200 rounded-xl max-w-md w-full p-6 shadow-2xl text-black">
        <div className="flex justify-between items-center mb-4 pb-3 border-b border-gray-200">
          <h3 className="text-lg font-bold text-black">Generate Compliance Report</h3>
          <button
            onClick={onClose}
            className="text-black hover:text-gray-700 text-xl font-bold"
          >
            &times;
          </button>
        </div>

        {errorMessage && (
          <div className="mb-4 p-3 bg-red-50 border border-red-300 rounded text-red-800 text-xs">
            {errorMessage}
          </div>
        )}

        <form onSubmit={handleGenerate} className="space-y-4">
          <div>
            <label className="block text-xs font-bold text-black mb-1">
              Select Scan
            </label>
            <select
              value={effectiveScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="w-full bg-white border border-gray-300 rounded-md px-3 py-2 text-sm text-black focus:outline-none focus:ring-1 focus:ring-black"
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
            <label className="block text-xs font-bold text-black mb-1">
              Report Format
            </label>
            <div className="grid grid-cols-3 gap-2">
              {['JSON', 'SARIF', 'HTML'].map((fmt) => (
                <button
                  key={fmt}
                  type="button"
                  onClick={() => setSelectedFormat(fmt)}
                  className={`py-2 px-3 text-xs font-bold rounded-lg border text-center transition ${
                    selectedFormat === fmt
                      ? 'bg-black text-white border-black ring-1 ring-black'
                      : 'bg-white text-black border-gray-300 hover:bg-gray-100'
                  }`}
                >
                  {fmt}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-xs text-gray-600">
              {selectedFormat === 'SARIF'
                ? 'OASIS SARIF v2.1.0 format for GitHub Code Scanning and CI/CD pipelines.'
                : selectedFormat === 'HTML'
                  ? 'Self-contained interactive HTML executive summary.'
                  : 'Raw JSON finding structures and technical metadata.'}
            </p>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-gray-200">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-bold text-black bg-gray-100 hover:bg-gray-200 rounded-lg transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={generating || !effectiveScanId}
              className="px-5 py-2 text-xs font-bold text-white bg-black hover:bg-gray-800 rounded-lg transition disabled:opacity-50"
            >
              {generating ? 'Generating...' : 'Generate & Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
