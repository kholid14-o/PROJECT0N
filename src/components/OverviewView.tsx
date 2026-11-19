import React, { useEffect, useState } from 'react';
import { Copy, Check, RefreshCw, ArrowRight, ShieldCheck } from 'lucide-react';
import type {
  ConsoleTab,
  Environment,
  GatewayLogItem,
  GatewayMetrics,
  Project,
} from '../types';
import { formatTimeAgo } from '../utils/hmac';

interface OverviewViewProps {
  project: Project;
  environment: Environment;
  metrics: GatewayMetrics;
  gatewayLogs: GatewayLogItem[];
  onProjectUpdated: (updated: Project) => void;
  onNavigate: (tab: ConsoleTab) => void;
}

const PIPELINE_LAYERS = [
  {
    step: '01',
    name: 'Payload & Content-Type Guard',
    detail: 'Enforces application/json & 256 KB max body before parsing',
    code: '400 / 413',
  },
  {
    step: '02',
    name: 'API Key & Scope Verifier',
    detail: 'SHA-256 hash lookup, revocation check & scope authorization',
    code: '401 / 403',
  },
  {
    step: '03',
    name: 'Sliding-Window Rate Limiter',
    detail: 'Per-project quota with X-RateLimit-* & Retry-After headers',
    code: '429',
  },
  {
    step: '04',
    name: 'HMAC-SHA256 & Replay Guard',
    detail: 'Constant-time signature check & 300s timestamp tolerance',
    code: '401',
  },
  {
    step: '05',
    name: 'Idempotency Cache',
    detail: '24h deduplication key & SHA-256 payload conflict detection',
    code: '202 / 409',
  },
  {
    step: '06',
    name: 'Schema Validation & Async Queue',
    detail: 'Persists event, returns 202 Accepted, queues HMAC dispatch',
    code: '202 / 422',
  },
];

export function OverviewView({
  project,
  environment,
  metrics,
  gatewayLogs,
  onProjectUpdated,
  onNavigate,
}: OverviewViewProps) {
  const [projectName, setProjectName] = useState(project.name);
  const [rateLimit, setRateLimit] = useState(String(project.rate_limit_per_minute));
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [showSecret, setShowSecret] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setProjectName(project.name);
    setRateLimit(String(project.rate_limit_per_minute));
    setFeedback(null);
    setError(null);
  }, [project.id, project.name, project.rate_limit_per_minute]);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setFeedback(null);
    setError(null);
    try {
      const parsedLimit = Number.parseInt(rateLimit, 10);
      const res = await fetch(`/api/projects/${project.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: projectName,
          rate_limit_per_minute: Number.isFinite(parsedLimit) ? parsedLimit : -1,
        }),
      });
      const data = (await res.json()) as { project?: Project; error?: string };
      if (!res.ok || !data.project) {
        setError(data.error ?? 'Failed to save project settings.');
        return;
      }
      onProjectUpdated(data.project);
      setFeedback('Project settings updated.');
    } catch {
      setError('Network error while saving settings.');
    } finally {
      setSaving(false);
    }
  };

  const handleRotateSecret = async () => {
    setRotating(true);
    setFeedback(null);
    setError(null);
    try {
      const res = await fetch(`/api/projects/${project.id}/rotate-secret`, {
        method: 'POST',
      });
      const data = (await res.json()) as { project?: Project; error?: string };
      if (!res.ok || !data.project) {
        setError(data.error ?? 'Could not rotate signing secret.');
        return;
      }
      onProjectUpdated(data.project);
      setShowSecret(true);
      setFeedback('Signing secret rotated. Update your client X-Signature configuration.');
    } catch {
      setError('Network error while rotating secret.');
    } finally {
      setRotating(false);
    }
  };

  const handleCopySecret = async () => {
    await navigator.clipboard.writeText(project.webhook_signing_secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 1800);
  };

  const totalDeliveries =
    (metrics.deliveries.success ?? 0) +
    (metrics.deliveries.failed ?? 0) +
    (metrics.deliveries.pending ?? 0);

  return (
    <div className="space-y-6">
      {/* KPI Strip */}
      <section
        aria-label="Environment Metrics"
        className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 bg-white border border-[#E4DFD3] rounded-xl divide-y sm:divide-y-0 sm:divide-x divide-[#EFECE4]"
      >
        <div className="p-5">
          <p className="text-xs font-medium text-[#625F57]">Events Ingested ({environment.toUpperCase()})</p>
          <p className="mt-2 text-2xl font-bold text-[#171614] tabular-nums">
            {metrics.events_ingested}
          </p>
          <p className="mt-1 text-xs text-[#625F57]">Accepted via POST /v1/events</p>
        </div>
        <div className="p-5">
          <p className="text-xs font-medium text-[#625F57]">Active API Keys</p>
          <p className="mt-2 text-2xl font-bold text-[#171614] tabular-nums">
            {metrics.active_keys}
          </p>
          <p className="mt-1 text-xs text-[#625F57]">SHA-256 hashed · Scoped</p>
        </div>
        <div className="p-5">
          <p className="text-xs font-medium text-[#625F57]">Active Webhook Targets</p>
          <p className="mt-2 text-2xl font-bold text-[#171614] tabular-nums">
            {metrics.active_endpoints}
          </p>
          <p className="mt-1 text-xs text-[#625F57]">
            <span className="tabular-nums">{totalDeliveries}</span> total attempts logged
          </p>
        </div>
        <div className="p-5">
          <p className="text-xs font-medium text-[#625F57]">Gateway Security Blocks</p>
          <p className="mt-2 text-2xl font-bold text-[#B91C1C] tabular-nums">
            {metrics.blocked_requests}
          </p>
          <p className="mt-1 text-xs text-[#625F57]">401 / 403 / 409 / 413 / 422 / 429</p>
        </div>
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* 6-Layer Security Pipeline */}
        <section className="xl:col-span-7 bg-white border border-[#E4DFD3] rounded-xl">
          <div className="px-6 py-4 border-b border-[#EFECE4] flex items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-bold text-[#171614]">
                API Entry Point Security Pipeline
              </h2>
              <p className="text-xs text-[#625F57] mt-0.5">
                Every request to <code className="font-mono">POST /v1/events</code> passes all 6 checkpoints sequentially
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('playground')}
              className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <span>Test Pipeline</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-[#EFECE4]">
            {PIPELINE_LAYERS.map((layer) => (
              <div
                key={layer.step}
                className="px-6 py-3.5 flex items-center justify-between gap-4 hover:bg-[#FAF9F6] transition-colors"
              >
                <div className="flex items-start gap-3.5 min-w-0">
                  <span className="font-mono text-xs font-semibold text-[#625F57] pt-0.5 tabular-nums shrink-0">
                    {layer.step}
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-[#171614]">{layer.name}</p>
                    <p className="text-xs text-[#625F57] mt-0.5">{layer.detail}</p>
                  </div>
                </div>
                <span className="font-mono text-xs text-[#3D3A34] whitespace-nowrap shrink-0 tabular-nums">
                  HTTP {layer.code}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* Project Settings & HMAC Signing Secret */}
        <section className="xl:col-span-5 bg-white border border-[#E4DFD3] rounded-xl">
          <div className="px-6 py-4 border-b border-[#EFECE4]">
            <h2 className="text-base font-bold text-[#171614]">
              Project Gateway Configuration
            </h2>
            <p className="text-xs text-[#625F57] mt-0.5">
              Adjust dynamic rate limits and manage your HMAC ingestion secret
            </p>
          </div>

          <form onSubmit={handleSaveSettings} className="p-6 space-y-4">
            <div>
              <label
                htmlFor="proj-name-input"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                Project Name
              </label>
              <input
                id="proj-name-input"
                type="text"
                required
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>

            <div>
              <label
                htmlFor="proj-rate-limit-input"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                Rate Limit (requests per minute)
              </label>
              <input
                id="proj-rate-limit-input"
                type="number"
                min={1}
                max={10000}
                required
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value)}
                className="w-full px-3 py-2 text-sm font-mono tabular-nums bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
              <p className="mt-1 text-[11px] text-[#625F57]">
                Set to e.g. <code className="font-mono">3</code> temporarily to test HTTP 429 throttling in the Playground.
              </p>
            </div>

            {error && (
              <div
                role="alert"
                className="text-xs text-[#991B1B] bg-[#FEF2F2] border border-[#FECACA] rounded-lg px-3 py-2"
              >
                {error}
              </div>
            )}
            {feedback && (
              <div className="text-xs text-[#166534] bg-[#F0FDF4] border border-[#BBF7D0] rounded-lg px-3 py-2">
                {feedback}
              </div>
            )}

            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] transition-colors cursor-pointer disabled:opacity-60"
            >
              {saving ? 'Saving...' : 'Save Configuration'}
            </button>
          </form>

          <div className="px-6 py-5 border-t border-[#EFECE4] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#165B29]" />
                <span className="text-xs font-semibold text-[#171614]">
                  Ingestion HMAC Signing Secret
                </span>
              </div>
              <button
                type="button"
                onClick={() => setShowSecret((prev) => !prev)}
                className="text-xs font-medium text-[#625F57] hover:text-[#171614] underline cursor-pointer"
              >
                {showSecret ? 'Hide' : 'Reveal'}
              </button>
            </div>

            <div className="flex items-center gap-2">
              <code className="flex-1 px-3 py-2 text-xs font-mono bg-[#F6F4EE] border border-[#E4DFD3] rounded-lg truncate text-[#171614]">
                {showSecret
                  ? project.webhook_signing_secret
                  : `${project.webhook_signing_secret.slice(0, 14)}••••••••••••••••••••••••`}
              </code>
              <button
                type="button"
                onClick={handleCopySecret}
                aria-label="Copy signing secret"
                className="p-2 border border-[#DCD6C8] rounded-lg bg-white hover:bg-[#FAF9F6] text-[#171614] cursor-pointer"
              >
                {copiedSecret ? <Check className="w-4 h-4 text-[#15803D]" /> : <Copy className="w-4 h-4" />}
              </button>
              <button
                type="button"
                onClick={handleRotateSecret}
                disabled={rotating}
                aria-label="Rotate signing secret"
                className="px-3 py-2 text-xs font-medium border border-[#DCD6C8] rounded-lg bg-white hover:bg-[#FAF9F6] text-[#171614] flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Rotate</span>
              </button>
            </div>
          </div>
        </section>
      </div>

      {/* Recent Gateway Audit Activity */}
      <section className="bg-white border border-[#E4DFD3] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#EFECE4] flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-[#171614]">Recent Gateway Audit Trail</h2>
            <p className="text-xs text-[#625F57] mt-0.5">
              Latest accepted events and security rejections on <code className="font-mono">/v1/*</code>
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('events')}
            className="text-xs font-semibold text-[#171614] hover:underline whitespace-nowrap cursor-pointer"
          >
            Inspect All Logs
          </button>
        </div>

        {gatewayLogs.length === 0 ? (
          <div className="px-6 py-10 text-center space-y-2">
            <p className="text-sm font-medium text-[#171614]">No gateway traffic recorded yet</p>
            <p className="text-xs text-[#625F57]">
              Send your first signed request in the API Playground to observe pipeline decisions.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#EFECE4] text-[11px] font-semibold text-[#625F57] bg-[#FAF9F6]">
                  <th className="py-2.5 px-6">Status</th>
                  <th className="py-2.5 px-4">Endpoint</th>
                  <th className="py-2.5 px-4">Error Code / Result</th>
                  <th className="py-2.5 px-4 text-right">Latency</th>
                  <th className="py-2.5 px-6 text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EFECE4] text-xs">
                {gatewayLogs.slice(0, 6).map((log) => (
                  <tr key={log.id} className="hover:bg-[#FAF9F6]">
                    <td className="py-2.5 px-6 font-mono font-semibold tabular-nums whitespace-nowrap">
                      <span
                        className={
                          log.status_code < 400 ? 'text-[#15803D]' : 'text-[#B91C1C]'
                        }
                      >
                        {log.status_code} {log.status_code === 202 ? 'Accepted' : log.status_code < 400 ? 'OK' : 'Rejected'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[#171614] whitespace-nowrap">
                      {log.method} {log.path}
                    </td>
                    <td className="py-2.5 px-4 text-[#3D3A34] max-w-md truncate">
                      {log.error_code ? (
                        <span className="font-mono text-[#B91C1C] font-medium">
                          {log.error_code}
                        </span>
                      ) : (
                        <span>{log.message ?? 'Accepted'}</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-[#625F57] whitespace-nowrap">
                      {log.latency_ms} ms
                    </td>
                    <td className="py-2.5 px-6 text-right text-[#625F57] whitespace-nowrap tabular-nums">
                      {formatTimeAgo(log.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
