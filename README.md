# GatePulse — Developer-First Webhook & Event Ingestion SaaS

GatePulse adalah platform **Developer-First Webhook & Event Ingestion SaaS** yang dirancang untuk menerima event aplikasi melalui pintu masuk API yang aman (**6-Layer API Security Gateway**), memvalidasi endpoint tujuan dari serangan **SSRF**, serta meneruskan webhook secara asinkron dengan tanda tangan digital **HMAC-SHA256** dan mekanisme **Auto-Retry** (exponential backoff).

---

## Fitur Utama

1. **Multi-Tenant Project Workspace & Pemisahan Lingkungan (`TEST` / `LIVE`)**
   - Registrasi & login developer berbasis session cookie (`HttpOnly`, ditandatangani HMAC-SHA256).
   - Akun demo bawaan (`dev@gatepulse.dev` / `gatepulse123`) yang langsung siap pakai beserta data contoh.
   - Setiap Project memiliki dua lingkungan terisolasi (`TEST` dan `LIVE`), konfigurasi `rate_limit_per_minute` dinamis, serta `webhook_signing_secret` (`whsec_...`) yang dapat di-rotate.

2. **Manajemen API Key Aman (Prefixed Keys & SHA-256 Hashing)**
   - Menghasilkan token berentropi 256-bit dengan format `gp_test_<random>` atau `gp_live_<random>`.
   - **Reveal-Once**: Kunci mentah hanya ditampilkan satu kali saat dibuat atau di-rotate; database hanya menyimpan `key_prefix` (16 karakter awal) dan `key_hash` (SHA-256).
   - **Scoped Permissions**: Mendukung cakupan izin granular (`events:write`, `endpoints:manage`, `logs:read`) serta fitur **Revoke** & **Rotate Key** seketika.

3. **6-Layer API Security Gateway (`POST /v1/events`)**
   Setiap permintaan masuk diproses berurutan melalui 6 pos pemeriksaan:
   - **Lapis 1 — Payload Size & Content-Type Guard**: Wajib `application/json`, batas maksimal **256 KB** (`413 Payload Too Large`), dan validasi JSON sebelum diproses (`400 Bad Request`).
   - **Lapis 2 — API Key Authenticator & Scope Verifier**: Verifikasi Bearer token via hash SHA-256, cek status aktif (`revoked_at IS NULL` → `401 INVALID_API_KEY`), dan cek scope izin (`403 INSUFFICIENT_SCOPE`).
   - **Lapis 3 — Sliding-Window Rate Limiter**: Pembatasan kuota per menit per Project & Environment dengan header standar `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, dan `Retry-After` (`429 RATE_LIMIT_EXCEEDED`).
   - **Lapis 4 — HMAC-SHA256 & Anti-Replay Guard**: Validasi header `X-Timestamp` (toleransi maksimal **300 detik**) dan verifikasi `X-Signature` dengan perbandingan constant-time `crypto.timingSafeEqual` (`401 TIMESTAMP_EXPIRED` / `401 INVALID_HMAC_SIGNATURE`).
   - **Lapis 5 — Idempotency Handler**: Deduplikasi `Idempotency-Key` selama 24 jam. Payload identik mengembalikan respons `202 Accepted` dari cache (`X-Idempotent-Replayed: true`), sedangkan payload berbeda dengan kunci sama ditolak dengan `409 IDEMPOTENCY_CONFLICT`.
   - **Lapis 6 — Schema Validation & Persistence**: Memvalidasi struktur `event_type` dan objek `data` (`422 VALIDATION_ERROR`), menyimpan event ke database, menjadwalkan pengiriman ke antrean, dan mengembalikan `202 Accepted`.

4. **Webhook Endpoint Registry & Proteksi Anti-SSRF**
   - Mendukung langganan pola event seperti `order.*`, `order.paid`, atau wildcard `*`.
   - **Validasi Anti-SSRF**: Melakukan pemeriksaan skema (`https://` wajib pada mode `LIVE`), memblokir hostname lokal (`localhost`, `*.local`, `*.internal`), serta melakukan resolusi DNS untuk menolak seluruh IP privat, loopback, link-local, dan metadata cloud (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`, dan `::ffff:*`) dengan status `422 Unprocessable Entity` (`SSRF_BLOCKED`).
   - **Built-in Sandbox Receiver Sink (`TEST` mode)**: Endpoint virtual (`https://sink.gatepulse.dev/r/...`) yang dapat diubah perilakunya secara langsung antara **Healthy (200 OK)**, **Server Error (500)**, dan **Timeout** untuk menguji retry dan memeriksa header keluar GatePulse.

5. **Asynchronous Queue Worker & Auto-Retry Engine**
   - Worker latar belakang mengirimkan HTTP `POST` ke setiap endpoint yang cocok dengan timeout 5 detik dan header tanda tangan GatePulse (`X-GatePulse-Event-Id`, `X-GatePulse-Timestamp`, `X-GatePulse-Signature`, `X-GatePulse-Attempt`).
   - Kegagalan pengiriman (HTTP non-2xx, error jaringan, atau timeout) memicu penjadwalan ulang otomatis dengan jeda **exponential backoff** (`10 detik` → `60 detik` → `300 detik`, maksimal 3 kali percobaan ulang otomatis).

6. **Developer Console & Interactive API Playground**
   - **Overview**: Ringkasan metrik per environment, visualisasi pipeline 6 lapis, konfigurasi rate limit, dan manajemen signing secret.
   - **API Keys**: Pembuatan, rotasi, pencabutan key, dan modal *Reveal-Once*.
   - **Webhook Endpoints**: Pendaftaran target URL, uji penolakan SSRF, dan inspeksi receipt Sandbox Sink.
   - **Events & Logs (Request Inspector)**: Pencarian event, filter status pengiriman, detail payload JSON, riwayat percobaan pengiriman, log penolakan keamanan gateway, dan tombol **Replay Event** manual.
   - **API Playground**: Pembuat request interaktif dengan kalkulasi `X-Signature` WebCrypto HMAC-SHA256 secara *real-time*, generator tombol key pengujian (Full / Read-Only 403), simulator *Expired Timestamp* & *1-Char Body Tamper*, serta pratinjau perintah `curl`.

---

## Arsitektur & Struktur Proyek

```text
├── server.ts                    # Entrypoint Express + Vite dev middleware + background queue worker
├── server/
│   ├── app.ts                   # Factory aplikasi Express (memasang /v1, /api, dan /health)
│   ├── db.ts                    # Skema SQLite (node:sqlite) dan seeder data demo deterministik
│   ├── security.ts              # Generator API Key, SHA-256, scrypt, HMAC-SHA256, rate limiter, validator
│   ├── ssrf.ts                  # Validasi URL webhook & pemblokiran rentang CIDR privat/DNS rebinding
│   ├── dispatcher.ts            # Antrean pengiriman asinkron, penandatanganan keluar, & auto-retry backoff
│   ├── consoleRoutes.ts         # API internal Developer Console (/api/*)
│   └── gatepulse.test.ts        # Test suite unit & integrasi untuk seluruh kriteria kelulusan
├── src/
│   ├── App.tsx                  # Shell utama Developer Console, sidebar, & pengalih TEST/LIVE
│   ├── types.ts                 # Definisi tipe TypeScript frontend
│   ├── utils/hmac.ts            # Utilitas WebCrypto HMAC-SHA256 & pemformat waktu
│   └── components/
│       ├── AuthScreen.tsx       # Halaman login, registrasi multi-tenant, & akses demo
│       ├── OverviewView.tsx     # Dasbor ringkasan, pipeline keamanan, & konfigurasi project
│       ├── ApiKeysView.tsx      # Manajemen API Key & modal Reveal-Once
│       ├── EndpointsView.tsx    # Registrasi webhook Anti-SSRF & Sandbox Receiver Sinks
│       ├── EventsInspectorView.tsx # Inspeksi payload, log pengiriman, gateway logs, & Manual Replay
│       ├── PlaygroundView.tsx   # Sandbox interaktif untuk menguji seluruh lapisan keamanan
│       └── ErrorDocsView.tsx    # Referensi kode error standar HTTP API Gateway
├── index.html                   # Entry HTML & Google Fonts (Plus Jakarta Sans, DM Sans, JetBrains Mono)
└── package.json
```

---

## Teknologi yang Digunakan

- **Runtime & Backend**: Node.js (v22+), Express, TypeScript, `node:sqlite` (`DatabaseSync` dengan mode WAL), `node:crypto`, `node:dns/promises`
- **Frontend**: React 19, Vite, Tailwind CSS v4, Lucide Icons, Web Crypto API
- **Pengujian**: Node.js built-in test runner (`node:test` + `node:assert/strict`) dijalankan melalui `tsx`

---

## Instalasi & Menjalankan Secara Lokal

### Prasyarat
- **Node.js v22.x** atau lebih baru (diperlukan untuk modul bawaan `node:sqlite` dan fitur runtime modern).
- **npm**

### Langkah Menjalankan

1. **Instal dependensi**:
   ```bash
   npm install
   ```

2. **Konfigurasi Environment Variable (Opsional)**:
   Aplikasi dapat langsung berjalan tanpa konfigurasi manual. Untuk lingkungan produksi, Anda dapat mengatur variabel berikut:
   ```env
   PORT=3000
   SESSION_SECRET="ganti-dengan-secret-acak-panjang"
   ```

3. **Jalankan server development** (Backend API + Vite Frontend pada port `3000`):
   ```bash
   npm run dev
   ```
   Buka browser ke `http://localhost:3000`. Database SQLite (`gatepulse.db`) dan data demo akan otomatis dibuat pada saat pertama kali dijalankan.

4. **Build & jalankan mode produksi**:
   ```bash
   npm run build
   NODE_ENV=production npm start
   ```

5. **Typechecking**:
   ```bash
   npm run lint
   ```

---

## Menjalankan Pengujian Otomatis (Security & Feature Tests)

Suite pengujian di `server/gatepulse.test.ts` memverifikasi seluruh fungsi kriptografi murni, proteksi Anti-SSRF, dan 8 skenario kriteria kelulusan secara *end-to-end* melalui HTTP server nyata dan database SQLite *in-memory*:

```bash
npx --yes tsx --test server/gatepulse.test.ts
```

Skenario yang diuji secara otomatis:
1. Permintaan tanpa API Key atau dengan API Key berstatus *revoked* → `401 Unauthorized` (`INVALID_API_KEY`).
2. Permintaan menggunakan API Key tanpa scope `events:write` → `403 Forbidden` (`INSUFFICIENT_SCOPE`).
3. Permintaan dengan `X-Timestamp` lebih lama dari 300 detik → `401 Unauthorized` (`TIMESTAMP_EXPIRED`).
4. Perubahan 1 karakter pada body JSON tanpa memperbarui `X-Signature` → `401 Unauthorized` (`INVALID_HMAC_SIGNATURE`).
5. Melebihi batas `rate_limit_per_minute` pada Project → `429 Too Many Requests` beserta header `Retry-After`.
6. Pengiriman ulang identik dengan `Idempotency-Key` sama → `202 Accepted` dari cache (`X-Idempotent-Replayed: true`) tanpa duplikasi di database, dan `409 Conflict` (`IDEMPOTENCY_CONFLICT`) jika isi payload berbeda.
7. Pendaftaran endpoint ke IP lokal/privat (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `192.168.0.0/16`, `::1`, atau domain DNS rebinding) → `422 Unprocessable Entity` (`SSRF_BLOCKED`), serta payload > 256 KB → `413 Payload Too Large`.
8. Server penerima webhook klien mati / gagal merespons → GatePulse tetap membalas `202 Accepted` ke pengirim awal, mencatat kegagalan di `delivery_attempts`, dan menjadwalkan retry otomatis dengan jeda exponential backoff.

---

## Referensi API Gateway (`/v1`)

### 1. Ingest Event (`POST /v1/events`)

**Header Wajib**:
- `Content-Type: application/json`
- `Authorization: Bearer gp_test_...` (atau `gp_live_...`, membutuhkan scope `events:write`)
- `X-Timestamp: <unix_timestamp_detik>`
- `X-Signature: <hex_hmac_sha256>` (dihitung atas `${X-Timestamp}.${rawBody}` menggunakan `webhook_signing_secret` Project)
- `Idempotency-Key: <unique_key>` *(opsional namun sangat disarankan)*

**Contoh Perhitungan Tanda Tangan Digital (Node.js)**:
```js
import crypto from 'node:crypto';

const timestamp = Math.floor(Date.now() / 1000).toString();
const rawBody = JSON.stringify({
  event_type: 'order.paid',
  data: { order_id: 'ord_99481', amount_idr: 450000, currency: 'IDR' },
});

const signature = crypto
  .createHmac('sha256', process.env.GATEPULSE_SIGNING_SECRET)
  .update(`${timestamp}.${rawBody}`)
  .digest('hex');
```

**Contoh Respons Sukses (`202 Accepted`)**:
```json
{
  "id": "evt_0192b8c4d1a07e4f8c2a1b3d",
  "status": "accepted",
  "environment": "test",
  "event_type": "order.paid",
  "matched_endpoints": 2,
  "request_id": "req_a18f20c4b1",
  "created_at": "2026-11-19T11:25:36.000Z"
}
```

**Contoh Respons Penolakan Terstandar**:
```json
{
  "error": {
    "type": "authentication_error",
    "code": "INVALID_HMAC_SIGNATURE",
    "message": "Tanda tangan digital pada header X-Signature tidak cocok dengan payload dan timestamp yang dikirim.",
    "doc_url": "/docs/errors#INVALID_HMAC_SIGNATURE",
    "request_id": "req_8f92a10c4b"
  }
}
```

### 2. Endpoint Programatik Lainnya
- `GET /v1/events` *(scope: `logs:read`)* — Mengambil daftar event terbaru pada environment sesuai API Key.
- `POST /v1/events/:id/replay` *(scope: `events:write`)* — Menjadwalkan pengiriman ulang event secara manual.
- `POST /v1/endpoints` *(scope: `endpoints:manage`)* — Mendaftarkan URL webhook tujuan baru (melalui validasi Anti-SSRF).

---

## Verifikasi Webhook Keluar di Server Penerima

Saat GatePulse mengirimkan webhook ke server Anda, verifikasi header berikut menggunakan `signing_secret` milik endpoint terkait:
- `X-GatePulse-Event-Id`
- `X-GatePulse-Timestamp`
- `X-GatePulse-Signature` — `HMAC_SHA256("${X-GatePulse-Timestamp}.${rawRequestBody}", endpointSigningSecret)`
- `X-GatePulse-Attempt`
