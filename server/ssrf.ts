import dns from 'node:dns/promises';
import net from 'node:net';
import type { Environment } from './security.ts';

export type DnsLookupFn = (hostname: string) => Promise<Array<{ address: string; family: number }>>;

export const SANDBOX_SINK_HOST = 'sink.gatepulse.dev';

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return -1;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr4(ipInt: number, baseIp: string, prefixLen: number): boolean {
  const baseInt = ipv4ToInt(baseIp);
  if (ipInt < 0 || baseInt < 0) return false;
  const mask = prefixLen === 0 ? 0 : (0xffffffff << (32 - prefixLen)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.trim().toLowerCase();
  if (!ip) return true;

  const ipVersion = net.isIP(ip);
  if (ipVersion === 4) {
    const ipInt = ipv4ToInt(ip);
    if (ipInt < 0) return true;
    return (
      inCidr4(ipInt, '0.0.0.0', 8) || // Current network / unspecified
      inCidr4(ipInt, '10.0.0.0', 8) || // RFC1918 Private
      inCidr4(ipInt, '100.64.0.0', 10) || // CGNAT
      inCidr4(ipInt, '127.0.0.0', 8) || // Loopback
      inCidr4(ipInt, '169.254.0.0', 16) || // Link-local & AWS/GCP Metadata
      inCidr4(ipInt, '172.16.0.0', 12) || // RFC1918 Private
      inCidr4(ipInt, '192.0.0.0', 24) || // IETF Protocol Assignments
      inCidr4(ipInt, '192.0.2.0', 24) || // TEST-NET-1
      inCidr4(ipInt, '192.168.0.0', 16) || // RFC1918 Private
      inCidr4(ipInt, '198.18.0.0', 15) || // Benchmarking
      inCidr4(ipInt, '224.0.0.0', 4) || // Multicast
      inCidr4(ipInt, '240.0.0.0', 4) // Reserved / Broadcast
    );
  }

  if (ipVersion === 6) {
    // Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1 or ::ffff:7f00:1
    if (ip.startsWith('::ffff:')) {
      const suffix = ip.slice(7);
      if (net.isIP(suffix) === 4) {
        return isPrivateOrReservedIp(suffix);
      }
      // Hex form ::ffff:7f00:0001
      const hexParts = suffix.split(':');
      if (hexParts.length === 2) {
        const hi = Number.parseInt(hexParts[0], 16);
        const lo = Number.parseInt(hexParts[1], 16);
        if (Number.isFinite(hi) && Number.isFinite(lo)) {
          const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
          return isPrivateOrReservedIp(ipv4);
        }
      }
    }

    const normalized = ip.split('%')[0]; // Strip zone index
    if (normalized === '::' || normalized === '::1') return true;
    // Link-local fe80::/10 (fe80 - febf)
    if (/^fe[89ab][0-9a-f]:/i.test(normalized) || /^fe[89ab][0-9a-f]$/i.test(normalized)) {
      return true;
    }
    // Unique local fc00::/7 (fc00 - fdff)
    if (/^f[cd][0-9a-f]{2}:/i.test(normalized)) return true;
    // Multicast ff00::/8
    if (/^ff[0-9a-f]{2}:/i.test(normalized)) return true;
    return false;
  }

  // Invalid IP format should be treated as unsafe
  return true;
}

export type WebhookUrlValidationResult =
  | { ok: true; normalizedUrl: string; isSandboxSink: boolean }
  | { ok: false; code: 'INVALID_URL' | 'INSECURE_SCHEME' | 'SSRF_BLOCKED'; message: string };

const defaultDnsLookup: DnsLookupFn = async (hostname: string) => {
  return dns.lookup(hostname, { all: true });
};

export async function validateWebhookUrl(
  rawUrl: string,
  environment: Environment,
  dnsLookup: DnsLookupFn = defaultDnsLookup
): Promise<WebhookUrlValidationResult> {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      ok: false,
      code: 'INVALID_URL',
      message: 'URL endpoint webhook wajib diisi.',
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return {
      ok: false,
      code: 'INVALID_URL',
      message: 'Format URL tidak valid. Sertakan skema lengkap seperti https://api.example.com/webhooks.',
    };
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return {
      ok: false,
      code: 'INSECURE_SCHEME',
      message: 'Skema URL harus berupa https:// atau http://.',
    };
  }

  if (environment === 'live' && parsed.protocol !== 'https:') {
    return {
      ok: false,
      code: 'INSECURE_SCHEME',
      message: 'Pada lingkungan LIVE, URL webhook wajib menggunakan protokol https:// terenkripsi.',
    };
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname) {
    return {
      ok: false,
      code: 'INVALID_URL',
      message: 'Hostname pada URL webhook tidak valid.',
    };
  }

  // Managed virtual sandbox sink (TEST mode only)
  if (hostname === SANDBOX_SINK_HOST) {
    if (environment !== 'test') {
      return {
        ok: false,
        code: 'SSRF_BLOCKED',
        message: 'Managed Sandbox Sink hanya dapat digunakan di lingkungan TEST.',
      };
    }
    return {
      ok: true,
      normalizedUrl: parsed.toString(),
      isSandboxSink: true,
    };
  }

  // Block well-known local/internal hostnames immediately
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname === 'metadata.google.internal'
  ) {
    return {
      ok: false,
      code: 'SSRF_BLOCKED',
      message: `Akses ke hostname internal/lokal "${hostname}" ditolak oleh perlindungan Anti-SSRF.`,
    };
  }

  // Direct IP literal check
  if (net.isIP(hostname) !== 0) {
    if (isPrivateOrReservedIp(hostname)) {
      return {
        ok: false,
        code: 'SSRF_BLOCKED',
        message: `Alamat IP privat/loopback/reserved (${hostname}) dilarang demi mencegah serangan SSRF.`,
      };
    }
    return {
      ok: true,
      normalizedUrl: parsed.toString(),
      isSandboxSink: false,
    };
  }

  // DNS resolution check against private/reserved CIDR ranges
  try {
    const records = await dnsLookup(hostname);
    if (!records || records.length === 0) {
      return {
        ok: false,
        code: 'SSRF_BLOCKED',
        message: `Resolusi DNS untuk domain "${hostname}" tidak mengembalikan alamat IP yang valid.`,
      };
    }
    for (const record of records) {
      if (isPrivateOrReservedIp(record.address)) {
        return {
          ok: false,
          code: 'SSRF_BLOCKED',
          message: `Domain "${hostname}" mengarah ke IP privat/internal (${record.address}) dan diblokir oleh kebijakan Anti-SSRF.`,
        };
      }
    }
  } catch {
    return {
      ok: false,
      code: 'SSRF_BLOCKED',
      message: `Gagal melakukan verifikasi DNS untuk hostname "${hostname}". Pastikan domain dapat di-resolve ke IP publik.`,
    };
  }

  return {
    ok: true,
    normalizedUrl: parsed.toString(),
    isSandboxSink: false,
  };
}
