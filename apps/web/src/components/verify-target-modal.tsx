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
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white border border-gray-200 rounded-xl max-w-xl w-full p-6 shadow-2xl text-black flex flex-col">
        {/* Header */}
        <div className="flex justify-between items-start pb-4 border-b border-gray-200">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-black">Target Ownership Verification</h2>
            <p className="text-sm font-mono font-semibold text-black mt-1">{target.baseUrl}</p>
          </div>
          <button
            onClick={onClose}
            className="text-black hover:text-gray-700 p-1 rounded-md transition-colors font-bold text-base"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="py-4 space-y-5">
          {/* Status banner */}
          <div className="flex items-center justify-between bg-gray-50 p-3 rounded-lg border border-gray-200 text-sm">
            <span className="text-black font-semibold">Authorization Status:</span>
            <span
              className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                isAuthorized
                  ? 'bg-emerald-50 text-emerald-800 border border-emerald-300'
                  : 'bg-amber-50 text-amber-800 border border-amber-300'
              }`}
            >
              {isAuthorized ? 'AUTHORIZED' : target.authorization}
            </span>
          </div>

          {success && (
            <div className="p-3 bg-emerald-50 border border-emerald-300 rounded-lg text-emerald-800 text-xs flex items-center gap-2 font-medium">
              <span className="font-bold text-emerald-700 text-base">✓</span>
              {success}
            </div>
          )}

          {error && (
            <div className="p-3 bg-red-50 border border-red-300 rounded-lg text-red-800 text-xs">
              <span className="font-bold block mb-0.5">Verification Error:</span>
              {error}
            </div>
          )}

          {/* Verification Method Tabs */}
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-black mb-2">
              Verification Method
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setMethod('HTTP_WELL_KNOWN')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  method === 'HTTP_WELL_KNOWN'
                    ? 'bg-gray-100 border-black text-black ring-1 ring-black'
                    : 'bg-white border-gray-200 text-gray-700 hover:bg-gray-50'
                }`}
              >
                <div className="font-bold text-sm text-black">HTTP .well-known</div>
                <div className="text-xs text-gray-600 mt-0.5">Host challenge file on web server</div>
              </button>
              <button
                type="button"
                onClick={() => setMethod('DNS_TXT')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  method === 'DNS_TXT'
                    ? 'bg-gray-100 border-black text-black ring-1 ring-black'
                    : 'bg-white border-gray-200 text-gray-700 hover:bg-gray-50'
                }`}
              >
                <div className="font-bold text-sm text-black">DNS TXT Record</div>
                <div className="text-xs text-gray-600 mt-0.5">Add TXT record to domain DNS</div>
              </button>
            </div>
          </div>

          {/* Challenge details */}
          {loadingChallenge ? (
            <div className="p-8 text-center text-sm text-gray-600 font-medium">
              Generating verification challenge tokens...
            </div>
          ) : challenge ? (
            <div className="bg-gray-50 p-4 rounded-lg border border-gray-200 space-y-4">
              {method === 'HTTP_WELL_KNOWN' ? (
                <>
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-bold text-black">1. Required File Path:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.wellKnownPath, 'path')}
                        className="text-black underline hover:text-gray-700 text-xs font-bold"
                      >
                        {copiedField === 'path' ? 'Copied!' : 'Copy Path'}
                      </button>
                    </div>
                    <code className="block bg-white p-2.5 rounded text-xs text-black font-mono break-all select-all border border-gray-300">
                      {challenge.wellKnownPath}
                    </code>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-bold text-black">2. Required File Content:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.expectedContent, 'content')}
                        className="text-black underline hover:text-gray-700 text-xs font-bold"
                      >
                        {copiedField === 'content' ? 'Copied!' : 'Copy Content'}
                      </button>
                    </div>
                    <code className="block bg-white p-2.5 rounded text-xs text-black font-mono break-all select-all border border-gray-300">
                      {challenge.expectedContent}
                    </code>
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-bold text-black">1. DNS Host / Name:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.dnsRecordName, 'dnsName')}
                        className="text-black underline hover:text-gray-700 text-xs font-bold"
                      >
                        {copiedField === 'dnsName' ? 'Copied!' : 'Copy Host'}
                      </button>
                    </div>
                    <code className="block bg-white p-2.5 rounded text-xs text-black font-mono break-all select-all border border-gray-300">
                      {challenge.dnsRecordName}
                    </code>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs font-bold text-black">2. DNS Record Type & Value:</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(challenge.dnsExpectedValue, 'dnsValue')}
                        className="text-black underline hover:text-gray-700 text-xs font-bold"
                      >
                        {copiedField === 'dnsValue' ? 'Copied!' : 'Copy Value'}
                      </button>
                    </div>
                    <div className="text-xs text-gray-700 mb-1">Type: <span className="font-mono font-bold text-black">TXT</span></div>
                    <code className="block bg-white p-2.5 rounded text-xs text-black font-mono break-all select-all border border-gray-300">
                      {challenge.dnsExpectedValue}
                    </code>
                  </div>
                </>
              )}

              <div className="text-[11px] text-gray-600 pt-1 font-medium">
                Challenge expires at:{' '}
                <span className="text-black font-mono font-bold">
                  {new Date(challenge.expiresAt).toLocaleTimeString()}
                </span>
              </div>
            </div>
          ) : null}
        </div>

        {/* Footer Actions */}
        <div className="flex justify-between items-center pt-4 border-t border-gray-200">
          <button
            type="button"
            onClick={() => loadOrInitiateChallenge(method)}
            disabled={loadingChallenge || checking}
            className="text-gray-700 hover:text-black text-xs font-bold transition-colors disabled:opacity-50"
          >
            Refresh Challenge
          </button>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              className="bg-gray-100 hover:bg-gray-200 text-black px-4 py-2 rounded-lg text-xs font-bold transition-colors"
            >
              Close
            </button>
            <button
              type="button"
              onClick={handleVerify}
              disabled={checking || loadingChallenge || !challenge || isAuthorized}
              className="bg-black hover:bg-gray-800 text-white px-5 py-2 rounded-lg text-xs font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
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
