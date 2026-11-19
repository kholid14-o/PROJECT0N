import React, { useState } from 'react';
import { Plus, ShieldAlert, Trash2, Webhook, Eye, X } from 'lucide-react';
import type { Environment, SandboxReceipt, WebhookEndpointItem } from '../types';
import { formatTimeAgo } from '../utils/hmac';

interface EndpointsViewProps {
  projectId: string;
  environment: Environment;
  endpoints: WebhookEndpointItem[];
  onRefresh: () => Promise<void>;
}

export function EndpointsView({
  projectId,
  environment,
  endpoints,
  onRefresh,
}: EndpointsViewProps) {
  const [url, setUrl] = useState('');
  const [description, setDescription] = useState('');
  const [eventsText, setEventsText] = useState('order.*, user.registered');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<{ message: string; code?: string } | null>(null);
  const [inspectSinkId, setInspectSinkId] = useState<string | null>(null);
  const [receipts, setReceipts] = useState<SandboxReceipt[]>([]);
  const [loadingReceipts, setLoadingReceipts] = useState(false);

  const handleAddEndpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const subscribedEvents = eventsText
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

      const res = await fetch(`/api/projects/${projectId}/endpoints`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          description,
          environment,
          subscribed_events: subscribedEvents.length > 0 ? subscribedEvents : ['*'],
        }),
      });
      const data = (await res.json()) as { error?: string; code?: string };
      if (!res.ok) {
        setError({
          message: data.error ?? 'Failed to register webhook endpoint.',
          code: data.code,
        });
        return;
      }
      setUrl('');
      setDescription('');
      await onRefresh();
    } catch {
      setError({ message: 'Network error while validating endpoint URL.' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleCreateSandboxSink = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch(`/api/projects/${projectId}/sandbox-sinks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: 'Interactive Sandbox Receiver',
          mode: 'healthy',
          subscribed_events: ['*'],
        }),
      });
      if (res.ok) {
        await onRefresh();
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleActive = async (ep: WebhookEndpointItem) => {
    await fetch(`/api/projects/${projectId}/endpoints/${ep.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: !ep.is_active }),
    });
    await onRefresh();
  };

  const handleDelete = async (endpointId: string) => {
    await fetch(`/api/projects/${projectId}/endpoints/${endpointId}`, {
      method: 'DELETE',
    });
    await onRefresh();
  };

  const handleChangeSinkMode = async (
    sinkId: string,
    mode: 'healthy' | 'server_error' | 'timeout'
  ) => {
    await fetch(`/api/projects/${projectId}/sandbox-sinks/${sinkId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
    await onRefresh();
  };

  const handleInspectSink = async (sinkId: string) => {
    setInspectSinkId(sinkId);
    setLoadingReceipts(true);
    try {
      const res = await fetch(`/api/projects/${projectId}/sandbox-sinks/${sinkId}/receipts`);
      const data = (await res.json()) as { receipts?: SandboxReceipt[] };
      setReceipts(data.receipts ?? []);
    } finally {
      setLoadingReceipts(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#171614]">
            Webhook Endpoints ({environment.toUpperCase()})
          </h2>
          <p className="text-xs text-[#625F57] mt-0.5">
            All target URLs undergo DNS resolution and CIDR Anti-SSRF checks before registration.
          </p>
        </div>
        {environment === 'test' && (
          <button
            type="button"
            onClick={handleCreateSandboxSink}
            disabled={submitting}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Create Built-in Sandbox Sink</span>
          </button>
        )}
      </div>

      {/* Register Endpoint Form */}
      <form
        onSubmit={handleAddEndpoint}
        className="bg-white border border-[#E4DFD3] rounded-xl p-6 space-y-4"
      >
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <h3 className="text-sm font-bold text-[#171614]">Register Destination URL</h3>
          <button
            type="button"
            onClick={() => {
              setUrl('http://127.0.0.1:8000/internal-hook');
              setError(null);
            }}
            className="text-xs font-medium text-[#625F57] hover:text-[#171614] underline cursor-pointer"
          >
            Fill 127.0.0.1 to test Anti-SSRF block
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-5">
            <label
              htmlFor="ep-url-input"
              className="block text-xs font-medium text-[#3D3A34] mb-1.5"
            >
              Endpoint URL {environment === 'live' ? '(HTTPS required)' : ''}
            </label>
            <input
              id="ep-url-input"
              type="text"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://api.yourapp.com/webhooks/gatepulse"
              className="w-full px-3 py-2 text-sm font-mono bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
            />
          </div>

          <div className="md:col-span-4">
            <label
              htmlFor="ep-events-input"
              className="block text-xs font-medium text-[#3D3A34] mb-1.5"
            >
              Subscribed Events (comma-separated)
            </label>
            <input
              id="ep-events-input"
              type="text"
              value={eventsText}
              onChange={(e) => setEventsText(e.target.value)}
              placeholder="order.*, payment.captured, *"
              className="w-full px-3 py-2 text-sm font-mono bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
            />
          </div>

          <div className="md:col-span-3">
            <label
              htmlFor="ep-desc-input"
              className="block text-xs font-medium text-[#3D3A34] mb-1.5"
            >
              Description
            </label>
            <input
              id="ep-desc-input"
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Order worker"
              className="w-full px-3 py-2 text-sm bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
            />
          </div>
        </div>

        {error && (
          <div
            role="alert"
            className="flex items-start gap-2.5 text-xs text-[#991B1B] bg-[#FEF2F2] border border-[#FECACA] rounded-lg px-3.5 py-2.5"
          >
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              {error.code && (
                <span className="font-mono font-bold mr-1.5">[{error.code}]</span>
              )}
              <span>{error.message}</span>
            </div>
          </div>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={submitting}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] transition-colors cursor-pointer disabled:opacity-60"
          >
            {submitting ? 'Validating DNS & Saving...' : 'Add Webhook Endpoint'}
          </button>
        </div>
      </form>

      {/* Endpoints List */}
      <section className="bg-white border border-[#E4DFD3] rounded-xl overflow-hidden">
        {endpoints.length === 0 ? (
          <div className="px-6 py-12 text-center space-y-2">
            <Webhook className="w-6 h-6 text-[#625F57] mx-auto" />
            <p className="text-sm font-semibold text-[#171614]">
              No webhook endpoints in {environment.toUpperCase()} mode
            </p>
            <p className="text-xs text-[#625F57]">
              Register a public HTTPS receiver URL or spin up a Built-in Sandbox Sink in TEST mode.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[#EFECE4]">
            {endpoints.map((ep) => (
              <div
                key={ep.id}
                className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4 hover:bg-[#FAF9F6]"
              >
                <div className="space-y-1.5 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-sm font-semibold text-[#171614] break-all">
                      {ep.url}
                    </span>
                    <span className="text-xs text-[#625F57]">·</span>
                    <span
                      className={`text-xs font-semibold ${
                        ep.is_active ? 'text-[#15803D]' : 'text-[#B45309]'
                      }`}
                    >
                      {ep.is_active ? 'Active' : 'Paused'}
                    </span>
                  </div>
                  <p className="text-xs text-[#625F57]">
                    {ep.description || 'Webhook consumer'} · Events:{' '}
                    <code className="font-mono text-[#171614]">
                      {ep.subscribed_events.join(', ')}
                    </code>{' '}
                    · Secret:{' '}
                    <code className="font-mono text-[#3D3A34]">
                      {ep.signing_secret.slice(0, 14)}••••
                    </code>
                  </p>
                </div>

                <div className="flex items-center gap-2 flex-wrap shrink-0">
                  {ep.sandbox_sink && (
                    <>
                      <label htmlFor={`sink-mode-${ep.id}`} className="sr-only">
                        Sandbox sink response mode
                      </label>
                      <select
                        id={`sink-mode-${ep.id}`}
                        value={ep.sandbox_sink.mode}
                        onChange={(e) =>
                          handleChangeSinkMode(
                            ep.sandbox_sink!.id,
                            e.target.value as 'healthy' | 'server_error' | 'timeout'
                          )
                        }
                        className="px-2.5 py-1.5 text-xs font-medium bg-white border border-[#DCD6C8] rounded-md text-[#171614] cursor-pointer"
                      >
                        <option value="healthy">Sink: Healthy (200 OK)</option>
                        <option value="server_error">Sink: Failing (HTTP 500)</option>
                        <option value="timeout">Sink: Offline (Timeout)</option>
                      </select>
                      <button
                        type="button"
                        onClick={() => handleInspectSink(ep.sandbox_sink!.id)}
                        className="px-2.5 py-1.5 text-xs font-medium border border-[#DCD6C8] rounded-md bg-white hover:bg-[#FAF9F6] text-[#171614] inline-flex items-center gap-1 cursor-pointer"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Receipts</span>
                      </button>
                    </>
                  )}
                  <button
                    type="button"
                    onClick={() => handleToggleActive(ep)}
                    className="px-2.5 py-1.5 text-xs font-medium border border-[#DCD6C8] rounded-md bg-white hover:bg-[#FAF9F6] text-[#171614] cursor-pointer"
                  >
                    {ep.is_active ? 'Pause' : 'Enable'}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDelete(ep.id)}
                    aria-label={`Delete endpoint ${ep.url}`}
                    className="p-1.5 border border-[#FECACA] rounded-md bg-[#FEF2F2] hover:bg-[#FEE2E2] text-[#991B1B] cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Sandbox Sink Receipts Modal */}
      {inspectSinkId && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="sink-receipts-title"
          className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4"
        >
          <div className="bg-white border border-[#E4DFD3] rounded-xl max-w-2xl w-full max-h-[82vh] flex flex-col">
            <div className="px-6 py-4 border-b border-[#EFECE4] flex items-center justify-between">
              <div>
                <h3 id="sink-receipts-title" className="text-base font-bold text-[#171614]">
                  Sandbox Sink Received Webhooks
                </h3>
                <p className="text-xs text-[#625F57] mt-0.5">
                  Outgoing deliveries signed with <code className="font-mono">X-GatePulse-Signature</code>
                </p>
              </div>
              <button
                type="button"
                onClick={() => setInspectSinkId(null)}
                aria-label="Close receipts modal"
                className="p-1 text-[#625F57] hover:text-[#171614] cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4">
              {loadingReceipts ? (
                <p className="text-xs text-[#625F57]">Loading delivered requests...</p>
              ) : receipts.length === 0 ? (
                <p className="text-xs text-[#625F57]">
                  No webhooks delivered to this sandbox sink yet. Trigger an event in the Playground.
                </p>
              ) : (
                receipts.map((rcp) => (
                  <div
                    key={rcp.id}
                    className="border border-[#E4DFD3] rounded-lg p-4 space-y-2.5 bg-[#FAF9F6]"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-semibold text-[#171614]">
                        {rcp.event_id}
                      </span>
                      <span
                        className={`font-mono font-semibold ${
                          rcp.responded_status < 400 ? 'text-[#15803D]' : 'text-[#B91C1C]'
                        }`}
                      >
                        HTTP {rcp.responded_status} · {formatTimeAgo(rcp.received_at)}
                      </span>
                    </div>
                    <pre className="text-[11px] font-mono bg-white border border-[#E4DFD3] rounded p-2.5 overflow-x-auto text-[#3D3A34]">
                      {JSON.stringify({ headers: rcp.headers, body: rcp.payload }, null, 2)}
                    </pre>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
