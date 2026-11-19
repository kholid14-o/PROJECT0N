import React, { useState } from 'react';
import { Copy, Check, KeyRound, Plus, RefreshCw, ShieldAlert, Trash2, X } from 'lucide-react';
import type { ApiKeyItem, ApiScope, Environment } from '../types';
import { formatTimeAgo } from '../utils/hmac';

interface ApiKeysViewProps {
  projectId: string;
  environment: Environment;
  apiKeys: ApiKeyItem[];
  onRefresh: () => Promise<void>;
  onUseInPlayground: (rawKey: string) => void;
}

const SCOPE_OPTIONS: Array<{ value: ApiScope; label: string; desc: string }> = [
  {
    value: 'events:write',
    label: 'events:write',
    desc: 'Ingest events via POST /v1/events and replay deliveries',
  },
  {
    value: 'endpoints:manage',
    label: 'endpoints:manage',
    desc: 'Register and configure webhook destination URLs',
  },
  {
    value: 'logs:read',
    label: 'logs:read',
    desc: 'Query ingested event logs and delivery histories',
  },
];

export function ApiKeysView({
  projectId,
  environment,
  apiKeys,
  onRefresh,
  onUseInPlayground,
}: ApiKeysViewProps) {
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [selectedScopes, setSelectedScopes] = useState<ApiScope[]>([
    'events:write',
    'logs:read',
  ]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState<{
    rawKey: string;
    name: string;
    environment: Environment;
  } | null>(null);
  const [copied, setCopied] = useState(false);

  const toggleScope = (scope: ApiScope) => {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    );
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch(`/api/projects/${projectId}/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          environment,
          scopes: selectedScopes,
        }),
      });
      const data = (await res.json()) as {
        api_key?: ApiKeyItem;
        raw_key?: string;
        error?: string;
      };
      if (!res.ok || !data.raw_key || !data.api_key) {
        setError(data.error ?? 'Failed to generate API key.');
        return;
      }
      setRevealedKey({
        rawKey: data.raw_key,
        name: data.api_key.name,
        environment: data.api_key.environment,
      });
      setName('');
      setShowCreate(false);
      await onRefresh();
    } catch {
      setError('Network error while creating API key.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    await fetch(`/api/projects/${projectId}/api-keys/${keyId}/revoke`, {
      method: 'POST',
    });
    await onRefresh();
  };

  const handleRotate = async (keyId: string) => {
    const res = await fetch(`/api/projects/${projectId}/api-keys/${keyId}/rotate`, {
      method: 'POST',
    });
    const data = (await res.json()) as {
      api_key?: ApiKeyItem;
      raw_key?: string;
    };
    if (res.ok && data.raw_key && data.api_key) {
      setRevealedKey({
        rawKey: data.raw_key,
        name: data.api_key.name,
        environment: data.api_key.environment,
      });
    }
    await onRefresh();
  };

  const handleCopyRevealed = async () => {
    if (!revealedKey) return;
    await navigator.clipboard.writeText(revealedKey.rawKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#171614]">
            API Keys ({environment.toUpperCase()} Environment)
          </h2>
          <p className="text-xs text-[#625F57] mt-0.5">
            Keys are hashed with SHA-256 at creation. Full secret keys are displayed once and never stored in plain text.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setShowCreate((prev) => !prev);
            setError(null);
          }}
          className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Create API Key</span>
        </button>
      </div>

      {showCreate && (
        <form
          onSubmit={handleCreateKey}
          className="bg-white border border-[#E4DFD3] rounded-xl p-6 space-y-5"
        >
          <div className="flex items-center justify-between border-b border-[#EFECE4] pb-3">
            <h3 className="text-sm font-bold text-[#171614]">
              Generate New {environment.toUpperCase()} Secret Key (gp_{environment}_...)
            </h3>
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              aria-label="Close create key form"
              className="p-1 text-[#625F57] hover:text-[#171614] cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label
                htmlFor="new-key-name"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                Key Name
              </label>
              <input
                id="new-key-name"
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Payment Microservice Ingest"
                className="w-full px-3 py-2 text-sm bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
              <p className="mt-1.5 text-[11px] text-[#625F57]">
                Generates a 256-bit cryptographic token prefixed with{' '}
                <code className="font-mono">gp_{environment}_</code>.
              </p>
            </div>

            <div>
              <span className="block text-xs font-medium text-[#3D3A34] mb-1.5">
                Scoped Permissions
              </span>
              <div className="space-y-2">
                {SCOPE_OPTIONS.map((opt) => (
                  <label
                    key={opt.value}
                    className="flex items-start gap-2.5 text-xs cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={selectedScopes.includes(opt.value)}
                      onChange={() => toggleScope(opt.value)}
                      className="mt-0.5 rounded border-[#DCD6C8]"
                    />
                    <span>
                      <code className="font-mono font-semibold text-[#171614]">
                        {opt.label}
                      </code>
                      <span className="block text-[#625F57]">{opt.desc}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="text-xs text-[#991B1B] bg-[#FEF2F2] border border-[#FECACA] rounded-lg px-3 py-2"
            >
              {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2 border-t border-[#EFECE4]">
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="px-3.5 py-2 text-xs font-medium text-[#625F57] hover:text-[#171614] cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors cursor-pointer disabled:opacity-60"
            >
              {submitting ? 'Generating...' : 'Generate Key'}
            </button>
          </div>
        </form>
      )}

      {/* Keys Table */}
      <section className="bg-white border border-[#E4DFD3] rounded-xl overflow-hidden">
        {apiKeys.length === 0 ? (
          <div className="px-6 py-12 text-center space-y-3">
            <KeyRound className="w-6 h-6 text-[#625F57] mx-auto" />
            <div className="space-y-1">
              <p className="text-sm font-semibold text-[#171614]">
                No API keys in {environment.toUpperCase()} environment
              </p>
              <p className="text-xs text-[#625F57]">
                Create a scoped secret key to authenticate requests to POST /v1/events.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] cursor-pointer"
            >
              Create First {environment.toUpperCase()} Key
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#EFECE4] text-[11px] font-semibold text-[#625F57] bg-[#FAF9F6]">
                  <th className="py-3 px-6">Name</th>
                  <th className="py-3 px-4">Key Prefix</th>
                  <th className="py-3 px-4">Scopes</th>
                  <th className="py-3 px-4">Last Used</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EFECE4] text-xs">
                {apiKeys.map((key) => {
                  const isRevoked = Boolean(key.revoked_at);
                  return (
                    <tr key={key.id} className="hover:bg-[#FAF9F6]">
                      <td className="py-3.5 px-6 font-semibold text-[#171614] whitespace-nowrap">
                        {key.name}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[#3D3A34] whitespace-nowrap">
                        {key.key_prefix}••••••••
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[#3D3A34]">
                        {key.scopes.join(' · ')}
                      </td>
                      <td className="py-3.5 px-4 text-[#625F57] tabular-nums whitespace-nowrap">
                        {formatTimeAgo(key.last_used_at)}
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap font-medium">
                        {isRevoked ? (
                          <span className="text-[#B91C1C]">Revoked</span>
                        ) : (
                          <span className="text-[#15803D]">Active</span>
                        )}
                      </td>
                      <td className="py-3.5 px-6 text-right whitespace-nowrap">
                        {!isRevoked ? (
                          <div className="inline-flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => handleRotate(key.id)}
                              aria-label={`Rotate key ${key.name}`}
                              className="px-2.5 py-1 text-[11px] font-medium border border-[#DCD6C8] rounded-md bg-white hover:bg-[#FAF9F6] text-[#171614] inline-flex items-center gap-1 cursor-pointer"
                            >
                              <RefreshCw className="w-3 h-3" />
                              <span>Rotate</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleRevoke(key.id)}
                              aria-label={`Revoke key ${key.name}`}
                              className="px-2.5 py-1 text-[11px] font-medium border border-[#FECACA] rounded-md bg-[#FEF2F2] hover:bg-[#FEE2E2] text-[#991B1B] inline-flex items-center gap-1 cursor-pointer"
                            >
                              <Trash2 className="w-3 h-3" />
                              <span>Revoke</span>
                            </button>
                          </div>
                        ) : (
                          <span className="text-[#625F57] text-[11px]">
                            Revoked {formatTimeAgo(key.revoked_at)}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Reveal-Once Modal */}
      {revealedKey && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="reveal-key-title"
          className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4"
        >
          <div className="bg-white border border-[#E4DFD3] rounded-xl max-w-lg w-full p-6 space-y-5">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <ShieldAlert className="w-5 h-5 text-[#B45309] shrink-0 mt-0.5" />
                <div>
                  <h3 id="reveal-key-title" className="text-base font-bold text-[#171614]">
                    Save Your Secret API Key Now
                  </h3>
                  <p className="text-xs text-[#625F57] mt-1 leading-relaxed">
                    Key <strong>{revealedKey.name}</strong> ({revealedKey.environment.toUpperCase()})
                    was created. GatePulse only retains its SHA-256 hash and cannot display this
                    secret again after closing this window.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setRevealedKey(null)}
                aria-label="Close secret key modal"
                className="p-1 text-[#625F57] hover:text-[#171614] cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center gap-2">
              <code className="flex-1 px-3 py-2.5 text-xs font-mono bg-[#F6F4EE] border border-[#DCD6C8] rounded-lg break-all text-[#171614]">
                {revealedKey.rawKey}
              </code>
              <button
                type="button"
                onClick={handleCopyRevealed}
                aria-label="Copy secret API key"
                className="px-3 py-2.5 border border-[#DCD6C8] rounded-lg bg-white hover:bg-[#FAF9F6] text-xs font-semibold text-[#171614] inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-[#15803D]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <div className="flex items-center justify-between gap-3 pt-2 border-t border-[#EFECE4]">
              <button
                type="button"
                onClick={() => {
                  const key = revealedKey.rawKey;
                  setRevealedKey(null);
                  onUseInPlayground(key);
                }}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors cursor-pointer"
              >
                Load into API Playground
              </button>
              <button
                type="button"
                onClick={() => setRevealedKey(null)}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] transition-colors cursor-pointer"
              >
                I Have Saved It
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
