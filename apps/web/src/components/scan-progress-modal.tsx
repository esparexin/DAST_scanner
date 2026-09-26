'use client';

import { useEffect, useState, useMemo } from 'react';
import { ScanStatus } from '@securityscan/contracts';
import { scansApi, type ApiScan } from '@/lib/api';
import { StatusBadge } from './status-badge';
import Link from 'next/link';

interface ScanProgressModalProps {
  scan: ApiScan | null;
  isOpen: boolean;
  onClose: () => void;
  onCancel?: (scanId: string) => Promise<void> | void;
}

interface EventLogEntry {
  id: string;
  timestamp: string;
  phase: string;
  message?: string;
  endpointsDiscovered?: number;
  findingsTotal?: number;
}

const ORDERED_PHASES: { status: ScanStatus; label: string; description: string }[] = [
  { status: ScanStatus.DISCOVERING, label: 'Discovery', description: 'Attack surface & endpoints' },
  { status: ScanStatus.PASSIVE_ANALYSIS, label: 'Passive', description: 'Header & content analysis' },
  { status: ScanStatus.ACTIVE_TESTING, label: 'Active', description: 'Vulnerability payload testing' },
  { status: ScanStatus.API_TESTING, label: 'API Testing', description: 'Schema & contract fuzzing' },
  { status: ScanStatus.VERIFYING, label: 'Verification', description: 'Confirming proof of issue' },
  { status: ScanStatus.EVIDENCE_COLLECTION, label: 'Evidence', description: 'Capturing reproducible PoCs' },
  { status: ScanStatus.REPORTING, label: 'Reporting', description: 'Generating audit report' },
];

const PHASE_PROGRESS_WEIGHTS: Record<string, number> = {
  [ScanStatus.CREATED]: 5,
  [ScanStatus.DISCOVERING]: 15,
  [ScanStatus.PASSIVE_ANALYSIS]: 30,
  [ScanStatus.ACTIVE_TESTING]: 55,
  [ScanStatus.API_TESTING]: 70,
  [ScanStatus.VERIFYING]: 85,
  [ScanStatus.EVIDENCE_COLLECTION]: 92,
  [ScanStatus.REPORTING]: 97,
  [ScanStatus.COMPLETED]: 100,
  [ScanStatus.FAILED]: 100,
  [ScanStatus.CANCELLED]: 100,
  [ScanStatus.TIMEOUT]: 100,
};

export function ScanProgressModal({ scan, isOpen, onClose, onCancel }: ScanProgressModalProps) {
  const [currentScan, setCurrentScan] = useState<ApiScan | null>(scan);
  const [logs, setLogs] = useState<EventLogEntry[]>([]);
  const [cancelling, setCancelling] = useState(false);

  useEffect(() => {
    setCurrentScan(scan);
    if (scan) {
      setLogs([
        {
          id: `init-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          phase: scan.status,
          message: scan.progress?.currentTask || `Scan status: ${scan.status}`,
          findingsTotal: scan.findingsCount,
        },
      ]);
    } else {
      setLogs([]);
    }
  }, [scan]);

  const isTerminal = useMemo(() => {
    if (!currentScan) return true;
    return (
      currentScan.status === ScanStatus.COMPLETED ||
      currentScan.status === ScanStatus.FAILED ||
      currentScan.status === ScanStatus.CANCELLED ||
      currentScan.status === ScanStatus.TIMEOUT
    );
  }, [currentScan]);

  // Connect SSE for active streaming
  useEffect(() => {
    if (!isOpen || !currentScan || isTerminal) return;

    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource(scansApi.getEventsUrl(currentScan._id));

      eventSource.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const phase = payload.phase || currentScan.status;
          const msg = payload.message || payload.progress?.currentTask;

          setCurrentScan((prev) => {
            if (!prev) return null;
            return {
              ...prev,
              status: phase,
              findingsCount: payload.findingsTotal ?? prev.findingsCount,
              progress: {
                ...prev.progress,
                phase,
                currentTask: msg || prev.progress?.currentTask,
                percent: payload.progress?.percent ?? PHASE_PROGRESS_WEIGHTS[phase] ?? prev.progress?.percent,
                endpointsDiscovered: payload.endpointsDiscovered ?? prev.progress?.endpointsDiscovered,
                findingsTotal: payload.findingsTotal ?? prev.progress?.findingsTotal,
              },
            };
          });

          setLogs((prev) => [
            ...prev,
            {
              id: `${Date.now()}-${Math.random()}`,
              timestamp: new Date().toLocaleTimeString(),
              phase,
              message: msg,
              endpointsDiscovered: payload.endpointsDiscovered,
              findingsTotal: payload.findingsTotal,
            },
          ]);

          if (
            phase === ScanStatus.COMPLETED ||
            phase === ScanStatus.FAILED ||
            phase === ScanStatus.CANCELLED
          ) {
            eventSource?.close();
          }
        } catch {
          // ignore parsing error
        }
      };

      eventSource.onerror = () => {
        eventSource?.close();
      };
    } catch {
      // EventSource failed to instantiate
    }

    return () => {
      eventSource?.close();
    };
  }, [isOpen, currentScan?._id, isTerminal]);

  if (!isOpen || !currentScan) return null;

  const currentPhaseIndex = ORDERED_PHASES.findIndex((p) => p.status === currentScan.status);
  const isCompleted = currentScan.status === ScanStatus.COMPLETED;
  const isFailed = currentScan.status === ScanStatus.FAILED;
  const isCancelled = currentScan.status === ScanStatus.CANCELLED;

  const progressPercent =
    currentScan.progress?.percent ??
    PHASE_PROGRESS_WEIGHTS[currentScan.status] ??
    (isCompleted ? 100 : 0);

  const handleCancelClick = async () => {
    if (!onCancel) return;
    try {
      setCancelling(true);
      await onCancel(currentScan._id);
      setCurrentScan((prev) => (prev ? { ...prev, status: ScanStatus.CANCELLED } : null));
    } finally {
      setCancelling(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-3xl w-full p-6 shadow-2xl text-gray-100 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex justify-between items-start pb-4 border-b border-gray-800">
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold tracking-tight text-white">Live Scan Progress</h2>
              <StatusBadge status={currentScan.status} />
              {!isTerminal && (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Streaming
                </span>
              )}
            </div>
            <p className="text-sm font-mono text-gray-400 mt-1">{currentScan.targetUrl}</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded-md transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto py-5 space-y-6 pr-1">
          {/* Progress Bar & Status */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="font-semibold text-gray-300">
                {currentScan.progress?.currentTask || `Phase: ${currentScan.status}`}
              </span>
              <span className="font-mono text-indigo-400 font-semibold">{progressPercent}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2.5 overflow-hidden">
              <div
                className={`h-2.5 rounded-full transition-all duration-500 ${
                  isFailed
                    ? 'bg-red-500'
                    : isCancelled
                      ? 'bg-amber-500'
                      : isCompleted
                        ? 'bg-emerald-500'
                        : 'bg-indigo-600'
                }`}
                style={{ width: `${Math.min(100, Math.max(4, progressPercent))}%` }}
              />
            </div>
          </div>

          {/* Phase Stepper */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3">
              Pipeline Stages
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
              {ORDERED_PHASES.map((p, idx) => {
                const isStepCompleted =
                  isCompleted || (currentPhaseIndex >= 0 && idx < currentPhaseIndex);
                const isStepActive = !isCompleted && !isFailed && !isCancelled && idx === currentPhaseIndex;
                const isStepFailed = (isFailed || isCancelled) && idx === currentPhaseIndex;

                return (
                  <div
                    key={p.status}
                    className={`p-2.5 rounded-lg border text-center transition-all ${
                      isStepCompleted
                        ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
                        : isStepActive
                          ? 'bg-indigo-950/50 border-indigo-500/80 text-white shadow-sm ring-1 ring-indigo-500/50'
                          : isStepFailed
                            ? 'bg-red-950/40 border-red-800/80 text-red-300'
                            : 'bg-gray-800/40 border-gray-800 text-gray-500'
                    }`}
                  >
                    <div className="flex justify-center mb-1">
                      {isStepCompleted ? (
                        <span className="h-4 w-4 rounded-full bg-emerald-500 text-black flex items-center justify-center text-[10px] font-bold">
                          ✓
                        </span>
                      ) : isStepActive ? (
                        <span className="h-4 w-4 rounded-full border-2 border-indigo-400 border-t-transparent animate-spin" />
                      ) : isStepFailed ? (
                        <span className="h-4 w-4 rounded-full bg-red-500 text-white flex items-center justify-center text-[10px] font-bold">
                          ✕
                        </span>
                      ) : (
                        <span className="h-4 w-4 rounded-full bg-gray-700 text-gray-400 flex items-center justify-center text-[10px]">
                          {idx + 1}
                        </span>
                      )}
                    </div>
                    <p className="text-xs font-semibold truncate">{p.label}</p>
                    <p className="text-[10px] text-gray-400 truncate hidden md:block">
                      {p.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-gray-800/50 p-4 rounded-lg border border-gray-800 text-sm">
            <div>
              <span className="text-xs text-gray-400">Profile</span>
              <p className="font-semibold text-white mt-0.5">{currentScan.profile}</p>
            </div>
            <div>
              <span className="text-xs text-gray-400">Findings Detected</span>
              <p className="font-semibold text-amber-400 mt-0.5">
                {currentScan.findingsCount ?? 0}
              </p>
            </div>
            <div>
              <span className="text-xs text-gray-400">Execution Mode</span>
              <p className="font-semibold text-gray-200 mt-0.5">
                {currentScan.dryRun ? 'Dry-Run Simulation' : 'Active Execution'}
              </p>
            </div>
            <div>
              <span className="text-xs text-gray-400">Started</span>
              <p className="font-semibold text-gray-200 mt-0.5 text-xs truncate">
                {new Date(currentScan.createdAt).toLocaleTimeString()}
              </p>
            </div>
          </div>

          {/* Live Terminal / Events Log Stream */}
          <div>
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Live Event Stream
              </h3>
              <span className="text-[11px] text-gray-500">{logs.length} events logged</span>
            </div>
            <div className="bg-black/80 rounded-lg p-3 font-mono text-xs text-gray-300 max-h-48 overflow-y-auto space-y-1.5 border border-gray-800 select-text">
              {logs.map((log) => (
                <div key={log.id} className="flex items-start gap-2 hover:bg-gray-900/60 p-0.5 rounded">
                  <span className="text-gray-500 shrink-0">[{log.timestamp}]</span>
                  <span className="text-indigo-400 font-semibold shrink-0">{log.phase}:</span>
                  <span className="text-gray-200 break-all">{log.message || 'Phase active'}</span>
                  {log.findingsTotal !== undefined && log.findingsTotal > 0 && (
                    <span className="ml-auto text-amber-400 font-bold shrink-0">
                      ({log.findingsTotal} findings)
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex justify-between items-center pt-4 border-t border-gray-800">
          <div>
            {!isTerminal && onCancel && (
              <button
                type="button"
                onClick={handleCancelClick}
                disabled={cancelling}
                className="bg-red-950/80 hover:bg-red-900 border border-red-800 text-red-200 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
              >
                {cancelling ? 'Cancelling...' : 'Cancel Scan'}
              </button>
            )}
          </div>
          <div className="flex items-center gap-3">
            {(currentScan.findingsCount ?? 0) > 0 && (
              <Link
                href={`/findings?scanId=${currentScan._id}`}
                className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-1.5 rounded-lg text-xs font-semibold transition-colors"
              >
                View Findings ({currentScan.findingsCount})
              </Link>
            )}
            <button
              type="button"
              onClick={onClose}
              className="bg-gray-800 hover:bg-gray-700 text-gray-200 px-4 py-1.5 rounded-lg text-xs font-semibold transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
