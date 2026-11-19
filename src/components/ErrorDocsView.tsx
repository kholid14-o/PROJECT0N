import React from 'react';

const ERROR_SPECS = [
  {
    status: '200 / 202',
    code: 'ACCEPTED',
    type: 'success',
    when: 'Request passed all 6 security layers and was persisted + queued for async webhook dispatch.',
    fix: 'No action required. Poll GET /v1/events or wait for signed webhook delivery.',
  },
  {
    status: '400',
    code: 'INVALID_JSON / INVALID_CONTENT_TYPE',
    type: 'invalid_request_error',
    when: 'Malformed JSON body or missing Content-Type: application/json header.',
    fix: 'Ensure Content-Type is application/json and body serializes cleanly.',
  },
  {
    status: '401',
    code: 'INVALID_API_KEY',
    type: 'authentication_error',
    when: 'Missing Bearer token, invalid prefix, non-existent SHA-256 hash, or revoked API key.',
    fix: 'Generate a new active key in API Keys and pass Authorization: Bearer gp_<env>_...',
  },
  {
    status: '401',
    code: 'TIMESTAMP_EXPIRED / INVALID_HMAC_SIGNATURE',
    type: 'authentication_error',
    when: 'X-Timestamp differs by more than 300 seconds from server time, or X-Signature fails constant-time HMAC verification.',
    fix: 'Compute HMAC-SHA256 over "${timestamp}.${rawBody}" using your project whsec_ secret.',
  },
  {
    status: '403',
    code: 'INSUFFICIENT_SCOPE',
    type: 'authorization_error',
    when: 'API Key is valid but lacks the required scope (e.g., events:write for POST /v1/events).',
    fix: 'Issue an API Key that includes the required permission scope.',
  },
  {
    status: '409',
    code: 'IDEMPOTENCY_CONFLICT',
    type: 'conflict_error',
    when: 'Idempotency-Key was reused within 24 hours with a different JSON payload hash.',
    fix: 'Generate a fresh Idempotency-Key for distinct payloads, or send identical body on retries.',
  },
  {
    status: '413',
    code: 'PAYLOAD_TOO_LARGE',
    type: 'payload_too_large',
    when: 'Raw request body exceeds the 256 KB gateway limit.',
    fix: 'Reduce payload size below 262,144 bytes before sending.',
  },
  {
    status: '422',
    code: 'SSRF_BLOCKED / VALIDATION_ERROR',
    type: 'invalid_request_error',
    when: 'JSON fields failed strict schema checks or webhook URL resolves to loopback/private/metadata IP ranges.',
    fix: 'Use a public HTTPS endpoint URL and provide valid event_type and data object.',
  },
  {
    status: '429',
    code: 'RATE_LIMIT_EXCEEDED',
    type: 'rate_limit_error',
    when: 'Request rate exceeded project rate_limit_per_minute sliding window.',
    fix: 'Honor the Retry-After response header and implement exponential backoff.',
  },
];

export function ErrorDocsView() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-[#171614]">
          Gateway Error Contract Reference
        </h2>
        <p className="text-xs text-[#625F57] mt-0.5">
          All rejections on <code className="font-mono">/v1/*</code> return an actionable JSON envelope with type, code, message, doc_url, and request_id.
        </p>
      </div>

      <div className="bg-white border border-[#E4DFD3] rounded-xl p-6 space-y-3">
        <h3 className="text-xs font-bold text-[#171614]">Standard Error Envelope</h3>
        <pre className="p-4 text-xs font-mono bg-[#171614] text-[#F8F6F1] rounded-lg overflow-x-auto">
{`{
  "error": {
    "type": "authentication_error",
    "code": "INVALID_HMAC_SIGNATURE",
    "message": "Tanda tangan digital pada header X-Signature tidak cocok dengan payload dan timestamp yang dikirim.",
    "doc_url": "/docs/errors#INVALID_HMAC_SIGNATURE",
    "request_id": "req_8f92a10c4b"
  }
}`}
        </pre>
      </div>

      <section className="bg-white border border-[#E4DFD3] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#EFECE4] text-[11px] font-semibold text-[#625F57] bg-[#FAF9F6]">
                <th className="py-3 px-6">HTTP Status</th>
                <th className="py-3 px-4">Error Code</th>
                <th className="py-3 px-4">Trigger Condition</th>
                <th className="py-3 px-6">Recommended Fix</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EFECE4] text-xs">
              {ERROR_SPECS.map((spec) => (
                <tr key={spec.code} className="hover:bg-[#FAF9F6]">
                  <td className="py-3.5 px-6 font-mono font-bold tabular-nums whitespace-nowrap">
                    <span
                      className={
                        spec.status.startsWith('2') ? 'text-[#15803D]' : 'text-[#B91C1C]'
                      }
                    >
                      {spec.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 font-mono font-semibold text-[#171614] whitespace-nowrap">
                    {spec.code}
                  </td>
                  <td className="py-3.5 px-4 text-[#3D3A34]">{spec.when}</td>
                  <td className="py-3.5 px-6 text-[#625F57]">{spec.fix}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
