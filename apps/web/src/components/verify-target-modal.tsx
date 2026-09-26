'use client';

import { useState, useEffect } from 'react';
import { targetsApi, type ApiTarget, type ApiTargetChallenge } from '@/lib/api';

interface VerifyTargetModalProps {
  target: ApiTarget | null;
  isOpen: boolean;
  onClose: () => void;
  onVerified?: (updatedTarget: ApiTarget) => void;
}

export function VerifyTargetModal({ target, isOpen, onClose, onVerified }: VerifyTargetModalProps) {
  const [method, setMethod] = useState<'HTTP_WELL_KNOWN' | 'DNS_TXT'>('HTTP_WELL_KNOWN');
  const [challenge, setChallenge] = useState<ApiTargetChallenge | null>(null);
  const [loadingChallenge, setLoadingChallenge] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && target) {
      setError(null);
      setSuccess(null);
      loadOrInitiateChallenge(method);
    } else {
      setChallenge(null);
    }
  }, [isOpen, target?._id, method]);

  async function loadOrInitiateChallenge(selectedMethod: 'HTTP_WELL_KNOWN' | 'DNS_TXT') {
    if (!target) return;
    try {
      setLoadingChallenge(true);
      setError(null);
      const res = await targetsApi.initiateVerification(target._id, selectedMethod);
      setChallenge(res.challenge);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to generate verification challenge';
      setError(msg);
    } finally {
      setLoadingChallenge(false);
    }
  }

  async function handleVerify() {
    if (!target) return;
    try {
      setChecking(true);
      setError(null);
      setSuccess(null);
      const res = await targetsApi.checkVerification(target._id, method);
      if (res.verified) {
        setSuccess('Target ownership verified successfully! Target is now AUTHORIZED.');
        if (onVerified && res.target) {
          onVerified(res.target);
        }
      } else {
        setError(res.result?.details || 'Verification check failed. Please ensure records are published.');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification failed';
      setError(msg);
    } finally {
      setChecking(false);
    }
  }

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  if (!isOpen || !target) return null;

  const isAuthorized = target.authorization === 'AUTHORIZED' || !!success;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-xl w-full p-6 shadow-2xl text-gray-100 flex flex-col">
        {/* Header */}
        <div className="flex justify-between items-start pb-4 border-b border-gray-800">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">Target Ownership Verification</h2>
            <p className="text-sm font-mono text-gray-400 mt-1">{target.baseUrl}</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded-md transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="py-4 space-y-5">
          {/* Status banner */}
          <div className="flex items-center justify-between bg-gray-800/60 p-3 rounded-lg border border-gray-800 text-sm">
            <span className="text-gray-300">Authorization Status:</span>
            <span
              className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
                isAuthorized
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
              }`}
            >
              {isAuthorized ? 'AUTHORIZED' : target.authorization}
            </span>
          </div>

          {success && (
            <div className="p-3 bg-emerald-950/80 border border-emerald-800 rounded-lg text-emerald-200 text-xs flex items-center gap-2">
              <span className="font-bold text-emerald-400 text-base">✓</span>
              {success}
            </div>
          )}

          {error && (
            <div className="p-3 bg-red-950/80 border border-red-800 rounded-lg text-red-200 text-xs">
              <span className="font-semibold block mb-0.5">Verification Error:</span>
              {error}
            </div>
          )}

          {/* Verification Method Tabs */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
              Verification Method
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setMethod('HTTP_WELL_KNOWN')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  method === 'HTTP_WELL_KNOWN'
                    ? 'bg-indigo-950/60 border-indigo-500 text-white'
                    : 'bg-gray-800/40 border-gray-800 text-gray-400 hover:bg-gray-800'
                }`}
              >
                <div className="font-semibold text-sm">HTTP .well-known</div>
                <div className="text-xs text-gray-400 mt-0.5">Host challenge file on web server</div>
              </button>
              <button
                type="button"
                onClick={() => setMethod('DNS_TXT')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  method === 'DNS_TXT'
                    ? 'bg-indigo-950/60 border-indigo-500 text-white'
                    : 'bg-gray-800/40 border-gray-800 text-gray-400 hover:bg-gray-800'
                }`}
              >
                <div className="font-semibold text-sm">DNS TXT Record</div>
                <div className="text-xs text-gray-400 mt-0.5">Add TXT record to domain DNS</div>
              </button>
            </div>
          </div>

          {/* Challenge details */}
          {loadingChallenge ? (
            <div className="p-8 text-center text-sm text-gray-500">
              Generating verification challenge tokens...
            </div>
          ) : challenge ? (
            <div className="bg-gray-800/50 p-4 rounded-lg border border-gray-800 space-y-4">
              {method === 'HTTP_WELL_KNOWN' ? (
                <>
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-semibold text-gray-300">1. Required File Path:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.wellKnownPath, 'path')}
                        className="text-indigo-400 hover:text-indigo-300 text-xs font-medium"
                      >
                        {copiedField === 'path' ? 'Copied!' : 'Copy Path'}
                      </button>
                    </div>
                    <code className="block bg-black/60 p-2 rounded text-xs text-indigo-300 font-mono break-all select-all border border-gray-700">
                      {challenge.wellKnownPath}
                    </code>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-semibold text-gray-300">2. Required File Content:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.expectedContent, 'content')}
                        className="text-indigo-400 hover:text-indigo-300 text-xs font-medium"
                      >
                        {copiedField === 'content' ? 'Copied!' : 'Copy Content'}
                      </button>
                    </div>
                    <code className="block bg-black/60 p-2 rounded text-xs text-emerald-300 font-mono break-all select-all border border-gray-700">
                      {challenge.expectedContent}
                    </code>
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-semibold text-gray-300">1. DNS Host / Name:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.dnsRecordName, 'dnsName')}
                        className="text-indigo-400 hover:text-indigo-300 text-xs font-medium"
                      >
                        {copiedField === 'dnsName' ? 'Copied!' : 'Copy Host'}
                      </button>
                    </div>
                    <code className="block bg-black/60 p-2 rounded text-xs text-indigo-300 font-mono break-all select-all border border-gray-700">
                      {challenge.dnsRecordName}
                    </code>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-semibold text-gray-300">2. DNS Record Type & Value:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.dnsExpectedValue, 'dnsValue')}
                        className="text-indigo-400 hover:text-indigo-300 text-xs font-medium"
                      >
                        {copiedField === 'dnsValue' ? 'Copied!' : 'Copy Value'}
                      </button>
                    </div>
                    <div className="text-xs text-gray-400 mb-1">Type: <span className="font-mono text-white">TXT</span></div>
                    <code className="block bg-black/60 p-2 rounded text-xs text-emerald-300 font-mono break-all select-all border border-gray-700">
                      {challenge.dnsExpectedValue}
                    </code>
                  </div>
                </>
              )}

              <div className="text-[11px] text-gray-400 pt-1">
                Challenge expires at:{' '}
                <span className="text-gray-300 font-mono">
                  {new Date(challenge.expiresAt).toLocaleTimeString()}
                </span>
              </div>
            </div>
          ) : null}
        </div>

        {/* Footer Actions */}
        <div className="flex justify-between items-center pt-4 border-t border-gray-800">
          <button
            type="button"
            onClick={() => loadOrInitiateChallenge(method)}
            disabled={loadingChallenge || checking}
            className="text-gray-400 hover:text-gray-200 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            Refresh Challenge
          </button>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-xs font-semibold transition-colors"
            >
              Close
            </button>
            <button
              type="button"
              onClick={handleVerify}
              disabled={checking || loadingChallenge || !challenge || isAuthorized}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-5 py-2 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {checking && (
                <span className="h-3 w-3 rounded-full border-2 border-white border-t-transparent animate-spin" />
              )}
              {isAuthorized ? 'Verified' : checking ? 'Verifying...' : 'Check Verification'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
