import React, { useEffect, useState } from 'react';
import { Play, KeyRound, Copy, Check, ShieldAlert } from 'lucide-react';
import type { Environment, Project } from '../types';
import { computeClientHmacSha256 } from '../utils/hmac';

interface PlaygroundViewProps {
  project: Project;
  environment: Environment;
  initialApiKey: string;
  onApiKeyChange: (key: string) => void;
  onEventSent: () => Promise<void>;
}

interface PlaygroundResponse {
  status: number;
  statusText: string;
  latencyMs: number;
  headers: Record<string, string>;
  body: unknown;
}

export function PlaygroundView({
  project,
  environment,
  initialApiKey,
  onApiKeyChange,
  onEventSent,
}: PlaygroundViewProps) {
  const [apiKeyInput, setApiKeyInput] = useState(initialApiKey);
  const [eventType, setEventType] = useState('order.paid');
  const [idempotencyKey, setIdempotencyKey] = useState(
    () => `req_${Math.random().toString(36).slice(2, 10)}`
  );
  const [timestampOffsetSec, setTimestampOffsetSec] = useState(0);
  const [tamperAfterSigning, setTamperAfterSigning] = useState(false);
  const [payloadText, setPayloadText] = useState(() =>
    JSON.stringify(
      {
        order_id: 'ord_78210',
        amount_idr: 275000,
        currency: 'IDR',
        customer_email: 'developer@example.com',
      },
      null,
      2
    )
  );
  const [computedSignature, setComputedSignature] = useState('');
  const [computedTimestamp, setComputedTimestamp] = useState(() =>
    Math.floor(Date.now() / 1000)
  );
  const [sending, setSending] = useState(false);
  const [generatingKey, setGeneratingKey] = useState(false);
  const [response, setResponse] = useState<PlaygroundResponse | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);

  useEffect(() => {
    if (initialApiKey) {
      setApiKeyInput(initialApiKey);
    }
  }, [initialApiKey]);

  const buildRawBody = (): string => {
    try {
      const parsedData = JSON.parse(payloadText);
      return JSON.stringify({ event_type: eventType, data: parsedData });
    } catch {
      // Allow sending malformed JSON if user intentionally tests Layer 1 JSON validation
      return `{"event_type":"${eventType}","data":${payloadText}}`;
    }
  };

  useEffect(() => {
    let active = true;
    const ts = Math.floor(Date.now() / 1000) + timestampOffsetSec;
    setComputedTimestamp(ts);
    const rawBody = buildRawBody();
    void computeClientHmacSha256(ts, rawBody, project.webhook_signing_secret).then((sig) => {
      if (active) setComputedSignature(sig);
    });
    return () => {
      active = false;
    };
  }, [eventType, payloadText, timestampOffsetSec, project.webhook_signing_secret]);

  const handleGenerateKey = async (scopes: string[], label: string) => {
    setGeneratingKey(true);
    try {
      const res = await fetch(`/api/projects/${project.id}/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: label,
          environment,
          scopes,
        }),
      });
      const data = (await res.json()) as { raw_key?: string };
      if (res.ok && data.raw_key) {
        setApiKeyInput(data.raw_key);
        onApiKeyChange(data.raw_key);
        await onEventSent();
      }
    } finally {
      setGeneratingKey(false);
    }
  };

  const handleSendRequest = async () => {
    setSending(true);
    const ts = Math.floor(Date.now() / 1000) + timestampOffsetSec;
    const rawBody = buildRawBody();
    const signature = await computeClientHmacSha256(
      ts,
      rawBody,
      project.webhook_signing_secret
    );
    setComputedTimestamp(ts);
    setComputedSignature(signature);

    // Optional 1-char tamper test without re-signing X-Signature
    const bodyToSend = tamperAfterSigning
      ? rawBody.slice(0, -1) + (rawBody.endsWith('}') ? ' }' : 'X')
      : rawBody;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Timestamp': String(ts),
      'X-Signature': signature,
    };
    if (apiKeyInput.trim()) {
      headers.Authorization = `Bearer ${apiKeyInput.trim()}`;
    }
    if (idempotencyKey.trim()) {
      headers['Idempotency-Key'] = idempotencyKey.trim();
    }

    const startMs = performance.now();
    try {
      const res = await fetch('/v1/events', {
        method: 'POST',
        headers,
        body: bodyToSend,
      });
      const latencyMs = Math.max(1, Math.round(performance.now() - startMs));
      const respHeaders: Record<string, string> = {};
      [
        'x-request-id',
        'x-ratelimit-limit',
        'x-ratelimit-remaining',
        'x-ratelimit-reset',
        'retry-after',
        'x-idempotent-replayed',
      ].forEach((h) => {
        const val = res.headers.get(h);
        if (val !== null) respHeaders[h] = val;
      });
      const parsedResp = await res.json().catch(() => ({}));
      setResponse({
        status: res.status,
        statusText: res.statusText,
        latencyMs,
        headers: respHeaders,
        body: parsedResp,
      });
      await onEventSent();
    } finally {
      setSending(false);
    }
  };

  const curlSnippet = `curl -X POST "${window.location.origin}/v1/events" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer ${apiKeyInput || `gp_${environment}_YOUR_KEY`}" \\
  -H "X-Timestamp: ${computedTimestamp}" \\
  -H "X-Signature: ${computedSignature}" \\${
    idempotencyKey ? `\n  -H "Idempotency-Key: ${idempotencyKey}" \\` : ''
  }
  -d '${buildRawBody()}'`;

  const handleCopyCurl = async () => {
    await navigator.clipboard.writeText(curlSnippet);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 1800);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#171614]">
            Interactive API Playground ({environment.toUpperCase()})
          </h2>
          <p className="text-xs text-[#625F57] mt-0.5">
            Sign payloads with live WebCrypto HMAC-SHA256 and test every security gate directly against <code className="font-mono">POST /v1/events</code>.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap sm:flex-nowrap">
          <button
            type="button"
            disabled={generatingKey}
            onClick={() =>
              handleGenerateKey(
                ['events:write', 'endpoints:manage', 'logs:read'],
                `Playground Full (${environment.toUpperCase()})`
              )
            }
            className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors inline-flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Generate Playground Key</span>
          </button>
          <button
            type="button"
            disabled={generatingKey}
            onClick={() =>
              handleGenerateKey(['logs:read'], `Playground Read-Only (${environment.toUpperCase()})`)
            }
            className="px-3 py-2 text-xs font-medium rounded-lg bg-white text-[#171614] border border-[#DCD6C8] hover:bg-[#FAF9F6] whitespace-nowrap cursor-pointer"
          >
            Read-Only Key (403)
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Request Builder */}
        <section className="xl:col-span-6 bg-white border border-[#E4DFD3] rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-bold text-[#171614] border-b border-[#EFECE4] pb-3">
            Request Builder
          </h3>

          <div>
            <label
              htmlFor="pg-api-key"
              className="block text-xs font-medium text-[#3D3A34] mb-1.5"
            >
              Authorization Bearer API Key (clear to test 401 INVALID_API_KEY)
            </label>
            <input
              id="pg-api-key"
              type="text"
              value={apiKeyInput}
              onChange={(e) => {
                setApiKeyInput(e.target.value);
                onApiKeyChange(e.target.value);
              }}
              placeholder={`gp_${environment}_...`}
              className="w-full px-3 py-2 text-xs font-mono bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="pg-event-type"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                event_type
              </label>
              <input
                id="pg-event-type"
                type="text"
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="pg-idem-key" className="text-xs font-medium text-[#3D3A34]">
                  Idempotency-Key
                </label>
                <button
                  type="button"
                  onClick={() =>
                    setIdempotencyKey(`req_${Math.random().toString(36).slice(2, 10)}`)
                  }
                  className="text-[11px] font-medium text-[#625F57] hover:text-[#171614] underline cursor-pointer"
                >
                  New Key
                </button>
              </div>
              <input
                id="pg-idem-key"
                type="text"
                value={idempotencyKey}
                onChange={(e) => setIdempotencyKey(e.target.value)}
                placeholder="Optional deduplication key"
                className="w-full px-3 py-2 text-xs font-mono bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="pg-payload-json"
              className="block text-xs font-medium text-[#3D3A34] mb-1.5"
            >
              Event Data (JSON object)
            </label>
            <textarea
              id="pg-payload-json"
              rows={7}
              value={payloadText}
              onChange={(e) => setPayloadText(e.target.value)}
              className="w-full p-3 text-xs font-mono bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
            />
          </div>

          {/* Security Test Controls */}
          <div className="border-t border-[#EFECE4] pt-4 space-y-3">
            <p className="text-xs font-bold text-[#171614]">Security Edge-Case Simulators</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="pg-ts-offset"
                  className="block text-[11px] font-medium text-[#625F57] mb-1"
                >
                  X-Timestamp Replay Window
                </label>
                <select
                  id="pg-ts-offset"
                  value={timestampOffsetSec}
                  onChange={(e) => setTimestampOffsetSec(Number(e.target.value))}
                  className="w-full px-2.5 py-1.5 text-xs bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg"
                >
                  <option value={0}>Current Server Time (Valid)</option>
                  <option value={-360}>Expired (-360s · Triggers 401)</option>
                </select>
              </div>

              <label className="flex items-center gap-2 text-xs text-[#3D3A34] pt-4 cursor-pointer">
                <input
                  type="checkbox"
                  checked={tamperAfterSigning}
                  onChange={(e) => setTamperAfterSigning(e.target.checked)}
                />
                <span>Tamper 1 char after signing (Test 401 HMAC)</span>
              </label>
            </div>
          </div>

          {/* Live Signature Preview */}
          <div className="bg-[#FAF9F6] border border-[#E4DFD3] rounded-lg p-3.5 space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-[#625F57]">
              <span>Live Computed X-Signature (HMAC-SHA256)</span>
              <span className="font-mono tabular-nums">X-Timestamp: {computedTimestamp}</span>
            </div>
            <code className="block text-[11px] font-mono text-[#171614] break-all">
              {computedSignature || 'Computing signature...'}
            </code>
          </div>

          <button
            type="button"
            onClick={handleSendRequest}
            disabled={sending}
            className="w-full py-2.5 px-4 text-sm font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-60"
          >
            <Play className="w-4 h-4" />
            <span>{sending ? 'Sending to Gateway...' : 'Send POST /v1/events'}</span>
          </button>
        </section>

        {/* Response Inspector + cURL */}
        <section className="xl:col-span-6 space-y-6">
          <div className="bg-white border border-[#E4DFD3] rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#EFECE4] pb-3">
              <h3 className="text-sm font-bold text-[#171614]">Gateway Response</h3>
              {response && (
                <div className="flex items-center gap-3 text-xs font-mono tabular-nums">
                  <span
                    className={`font-bold ${
                      response.status < 400 ? 'text-[#15803D]' : 'text-[#B91C1C]'
                    }`}
                  >
                    HTTP {response.status} {response.statusText}
                  </span>
                  <span className="text-[#625F57]">{response.latencyMs} ms</span>
                </div>
              )}
            </div>

            {!response ? (
              <div className="py-10 text-center space-y-1.5">
                <ShieldAlert className="w-5 h-5 text-[#625F57] mx-auto" />
                <p className="text-xs font-medium text-[#171614]">
                  Ready to fire a request
                </p>
                <p className="text-xs text-[#625F57]">
                  Generate a Playground Key above or paste an existing key, then click Send.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {Object.keys(response.headers).length > 0 && (
                  <div>
                    <p className="text-[11px] font-semibold text-[#625F57] mb-1.5">
                      Response Headers
                    </p>
                    <div className="bg-[#FAF9F6] border border-[#E4DFD3] rounded-lg p-3 space-y-1 text-[11px] font-mono">
                      {Object.entries(response.headers).map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-4">
                          <span className="text-[#625F57]">{k}:</span>
                          <span className="text-[#171614] font-medium tabular-nums">{v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <p className="text-[11px] font-semibold text-[#625F57] mb-1.5">
                    JSON Response Body
                  </p>
                  <pre className="p-4 text-xs font-mono bg-[#FAF9F6] border border-[#E4DFD3] rounded-lg whitespace-pre-wrap break-words text-[#171614]">
                    {JSON.stringify(response.body, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </div>

          <div className="bg-white border border-[#E4DFD3] rounded-xl p-6 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-[#171614]">Equivalent cURL Command</h3>
              <button
                type="button"
                onClick={handleCopyCurl}
                className="px-2.5 py-1 text-xs font-medium border border-[#DCD6C8] rounded-md bg-white hover:bg-[#FAF9F6] text-[#171614] inline-flex items-center gap-1.5 cursor-pointer"
              >
                {copiedCurl ? <Check className="w-3.5 h-3.5 text-[#15803D]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedCurl ? 'Copied' : 'Copy cURL'}</span>
              </button>
            </div>
            <pre className="p-3.5 text-[11px] font-mono bg-[#171614] text-[#F8F6F1] rounded-lg whitespace-pre-wrap break-all leading-relaxed">
              {curlSnippet}
            </pre>
          </div>
        </section>
      </div>
    </div>
  );
}
