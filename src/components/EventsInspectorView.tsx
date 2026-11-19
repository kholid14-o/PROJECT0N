import React, { useMemo, useState } from 'react';
import { RefreshCw, Search, RotateCcw } from 'lucide-react';
import type { Environment, EventItem, GatewayLogItem } from '../types';
import { formatShortDate, formatTimeAgo } from '../utils/hmac';

interface EventsInspectorViewProps {
  projectId: string;
  environment: Environment;
  events: EventItem[];
  gatewayLogs: GatewayLogItem[];
  onRefresh: () => Promise<void>;
}

export function EventsInspectorView({
  projectId,
  environment,
  events,
  gatewayLogs,
  onRefresh,
}: EventsInspectorViewProps) {
  const [subTab, setSubTab] = useState<'events' | 'gateway'>('events');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'failed' | 'pending'>('all');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(events[0]?.id ?? null);
  const [replayingId, setReplayingId] = useState<string | null>(null);
  const [replayFeedback, setReplayFeedback] = useState<string | null>(null);

  const filteredEvents = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events.filter((evt) => {
      const matchesText =
        !q ||
        evt.event_type.toLowerCase().includes(q) ||
        evt.id.toLowerCase().includes(q) ||
        (evt.idempotency_key?.toLowerCase().includes(q) ?? false);

      if (!matchesText) return false;
      if (statusFilter === 'all') return true;
      return evt.attempts.some((a) => a.status === statusFilter);
    });
  }, [events, search, statusFilter]);

  const activeEvent = useMemo(() => {
    return (
      filteredEvents.find((e) => e.id === selectedEventId) ??
      filteredEvents[0] ??
      null
    );
  }, [filteredEvents, selectedEventId]);

  const handleReplay = async (eventId: string, endpointId?: string) => {
    setReplayingId(eventId);
    setReplayFeedback(null);
    try {
      const res = await fetch(`/api/projects/${projectId}/events/${eventId}/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(endpointId ? { endpoint_id: endpointId } : {}),
      });
      const data = (await res.json()) as { queued_attempts?: number; error?: string };
      if (!res.ok) {
        setReplayFeedback(data.error ?? 'Failed to replay event.');
      } else {
        setReplayFeedback(
          `Queued ${data.queued_attempts ?? 1} manual replay delivery attempt(s).`
        );
        // Wait briefly for worker to process immediate delivery, then refresh
        setTimeout(() => {
          void onRefresh();
        }, 350);
      }
      await onRefresh();
    } finally {
      setReplayingId(null);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#171614]">
            Events & Request Inspector ({environment.toUpperCase()})
          </h2>
          <p className="text-xs text-[#625F57] mt-0.5">
            Inspect ingested event payloads, delivery attempt latencies, automatic retries, and gateway security rejections.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex gap-1 p-1 bg-[#EAE5DA] rounded-lg">
            <button
              type="button"
              onClick={() => setSubTab('events')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                subTab === 'events'
                  ? 'bg-white text-[#171614]'
                  : 'text-[#625F57] hover:text-[#171614]'
              }`}
            >
              Event Deliveries
            </button>
            <button
              type="button"
              onClick={() => setSubTab('gateway')}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                subTab === 'gateway'
                  ? 'bg-white text-[#171614]'
                  : 'text-[#625F57] hover:text-[#171614]'
              }`}
            >
              Gateway Security Logs
            </button>
          </div>
          <button
            type="button"
            onClick={() => void onRefresh()}
            aria-label="Refresh event logs"
            className="p-2 border border-[#DCD6C8] rounded-lg bg-white hover:bg-[#FAF9F6] text-[#171614] cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {subTab === 'events' ? (
        <>
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-[#625F57] absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="search"
                aria-label="Search events by type, ID, or idempotency key"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter by event_type (e.g. order.paid), evt_ ID, or Idempotency-Key..."
                className="w-full pl-9 pr-3 py-2 text-xs bg-white border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>

            <div className="flex gap-1 p-1 bg-[#EAE5DA] rounded-lg shrink-0">
              {(['all', 'success', 'failed', 'pending'] as const).map((status) => (
                <button
                  key={status}
                  type="button"
                  onClick={() => setStatusFilter(status)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md capitalize whitespace-nowrap cursor-pointer ${
                    statusFilter === status
                      ? 'bg-white text-[#171614] font-semibold'
                      : 'text-[#625F57] hover:text-[#171614]'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>
          </div>

          {filteredEvents.length === 0 ? (
            <div className="bg-white border border-[#E4DFD3] rounded-xl p-12 text-center space-y-2">
              <p className="text-sm font-semibold text-[#171614]">
                No matching events found in {environment.toUpperCase()} mode
              </p>
              <p className="text-xs text-[#625F57]">
                Send an event via the API Playground or clear your search filter.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
              {/* Left Master List */}
              <div className="lg:col-span-5 bg-white border border-[#E4DFD3] rounded-xl overflow-hidden divide-y divide-[#EFECE4]">
                {filteredEvents.map((evt) => {
                  const isSelected = activeEvent?.id === evt.id;
                  const succeeded = evt.attempts.filter((a) => a.status === 'success').length;
                  const failed = evt.attempts.filter((a) => a.status === 'failed').length;
                  const pending = evt.attempts.filter((a) => a.status === 'pending').length;

                  return (
                    <button
                      key={evt.id}
                      type="button"
                      onClick={() => {
                        setSelectedEventId(evt.id);
                        setReplayFeedback(null);
                      }}
                      className={`w-full text-left px-5 py-3.5 transition-colors cursor-pointer ${
                        isSelected ? 'bg-[#F5EFE4]' : 'hover:bg-[#FAF9F6]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-bold text-[#171614] truncate">
                          {evt.event_type}
                        </span>
                        <span className="text-[11px] text-[#625F57] tabular-nums shrink-0">
                          {formatTimeAgo(evt.created_at)}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-[#625F57]">
                        <span className="font-mono truncate">{evt.id}</span>
                        <span className="tabular-nums shrink-0">
                          {evt.attempts.length === 0
                            ? '0 matched'
                            : `${succeeded} ok · ${failed} err${pending ? ` · ${pending} queued` : ''}`}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Right Detail Inspector */}
              {activeEvent && (
                <div className="lg:col-span-7 bg-white border border-[#E4DFD3] rounded-xl overflow-hidden">
                  <div className="px-6 py-4 border-b border-[#EFECE4] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <h3 className="font-mono text-sm font-bold text-[#171614]">
                        {activeEvent.event_type}
                      </h3>
                      <p className="text-xs text-[#625F57] font-mono mt-0.5">
                        {activeEvent.id} · {formatShortDate(activeEvent.created_at)}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleReplay(activeEvent.id)}
                      disabled={replayingId === activeEvent.id}
                      className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>
                        {replayingId === activeEvent.id ? 'Queueing...' : 'Replay Event'}
                      </span>
                    </button>
                  </div>

                  {replayFeedback && (
                    <div className="mx-6 mt-4 text-xs text-[#166534] bg-[#F0FDF4] border border-[#BBF7D0] rounded-lg px-3 py-2">
                      {replayFeedback}
                    </div>
                  )}

                  <div className="p-6 space-y-6">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs border-b border-[#EFECE4] pb-4">
                      <div>
                        <span className="text-[#625F57] block">Source IP</span>
                        <span className="font-mono font-medium text-[#171614]">
                          {activeEvent.source_ip}
                        </span>
                      </div>
                      <div>
                        <span className="text-[#625F57] block">Idempotency-Key</span>
                        <span className="font-mono font-medium text-[#171614] break-all">
                          {activeEvent.idempotency_key ?? 'None'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[#625F57] block">Environment</span>
                        <span className="font-mono font-semibold text-[#171614] uppercase">
                          {activeEvent.environment}
                        </span>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-[#171614] mb-2">
                        Ingested JSON Payload
                      </h4>
                      <pre className="p-4 text-xs font-mono bg-[#FAF9F6] border border-[#E4DFD3] rounded-lg overflow-x-auto text-[#171614]">
                        {JSON.stringify(activeEvent.payload, null, 2)}
                      </pre>
                    </div>

                    <div className="border-t border-[#EFECE4] pt-5">
                      <h4 className="text-xs font-bold text-[#171614] mb-3">
                        Webhook Delivery Attempts ({activeEvent.attempts.length})
                      </h4>
                      {activeEvent.attempts.length === 0 ? (
                        <p className="text-xs text-[#625F57] py-2">
                          No active webhook endpoints subscribed to{' '}
                          <code className="font-mono">{activeEvent.event_type}</code> when this event arrived.
                        </p>
                      ) : (
                        <div className="divide-y divide-[#EFECE4]">
                          {activeEvent.attempts.map((attempt) => (
                            <div key={attempt.id} className="py-3.5 first:pt-0 last:pb-0 space-y-1.5">
                              <div className="flex items-center justify-between gap-3 flex-wrap">
                                <div className="flex items-center gap-2 text-xs">
                                  <span className="font-mono font-bold text-[#171614] tabular-nums">
                                    Attempt #{attempt.attempt_number}
                                  </span>
                                  <span className="text-[#625F57]">·</span>
                                  <span
                                    className={`font-semibold ${
                                      attempt.status === 'success'
                                        ? 'text-[#15803D]'
                                        : attempt.status === 'failed'
                                        ? 'text-[#B91C1C]'
                                        : 'text-[#B45309]'
                                    }`}
                                  >
                                    {attempt.status === 'success'
                                      ? `Succeeded (HTTP ${attempt.http_status_code})`
                                      : attempt.status === 'failed'
                                      ? `Failed${
                                          attempt.http_status_code
                                            ? ` (HTTP ${attempt.http_status_code})`
                                            : ''
                                        }`
                                      : 'Pending Retry'}
                                  </span>
                                </div>

                                <div className="flex items-center gap-3 text-[11px] text-[#625F57] font-mono tabular-nums">
                                  {attempt.latency_ms !== null && (
                                    <span>{attempt.latency_ms} ms</span>
                                  )}
                                  {attempt.attempted_at && (
                                    <span>{formatTimeAgo(attempt.attempted_at)}</span>
                                  )}
                                </div>
                              </div>

                              <p className="text-[11px] font-mono text-[#625F57] break-all">
                                Target: {attempt.endpoint_url}
                              </p>

                              {attempt.error_message && (
                                <p className="text-xs text-[#991B1B] font-medium">
                                  {attempt.error_message}
                                </p>
                              )}

                              {attempt.status === 'pending' && attempt.next_retry_at && (
                                <p className="text-[11px] text-[#B45309]">
                                  Scheduled automatic retry at {formatShortDate(attempt.next_retry_at)}
                                </p>
                              )}

                              {attempt.response_body && (
                                <pre className="text-[11px] font-mono bg-[#FAF9F6] rounded px-3 py-2 whitespace-pre-wrap break-words text-[#3D3A34]">
                                  {attempt.response_body}
                                </pre>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        /* Gateway Security Audit Table */
        <section className="bg-white border border-[#E4DFD3] rounded-xl overflow-hidden">
          {gatewayLogs.length === 0 ? (
            <div className="p-12 text-center text-xs text-[#625F57]">
              No gateway request logs recorded for {environment.toUpperCase()} yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[#EFECE4] text-[11px] font-semibold text-[#625F57] bg-[#FAF9F6]">
                    <th className="py-3 px-5">HTTP Status</th>
                    <th className="py-3 px-4">Request ID</th>
                    <th className="py-3 px-4">Route</th>
                    <th className="py-3 px-4">Code & Reason</th>
                    <th className="py-3 px-4 text-right">Latency</th>
                    <th className="py-3 px-5 text-right">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#EFECE4] text-xs">
                  {gatewayLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-[#FAF9F6]">
                      <td className="py-3 px-5 font-mono font-bold tabular-nums whitespace-nowrap">
                        <span
                          className={
                            log.status_code < 400 ? 'text-[#15803D]' : 'text-[#B91C1C]'
                          }
                        >
                          {log.status_code}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[#625F57] whitespace-nowrap">
                        {log.request_id}
                      </td>
                      <td className="py-3 px-4 font-mono text-[#171614] whitespace-nowrap">
                        {log.method} {log.path}
                      </td>
                      <td className="py-3 px-4">
                        {log.error_code && (
                          <span className="font-mono font-semibold text-[#B91C1C] mr-2">
                            {log.error_code}
                          </span>
                        )}
                        <span className="text-[#3D3A34]">{log.message}</span>
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-[#625F57] whitespace-nowrap">
                        {log.latency_ms} ms
                      </td>
                      <td className="py-3 px-5 text-right text-[#625F57] tabular-nums whitespace-nowrap">
                        {formatTimeAgo(log.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
