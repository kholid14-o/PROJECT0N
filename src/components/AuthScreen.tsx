import React, { useState } from 'react';
import { ArrowRight, KeyRound, ShieldCheck, Webhook, RefreshCw } from 'lucide-react';
import type { User } from '../types';

interface AuthScreenProps {
  onAuthenticated: (user: User) => void;
}

export function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const endpoint = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          mode === 'login' ? { email, password } : { name, email, password }
        ),
      });
      const data = (await res.json()) as { user?: User; error?: string };
      if (!res.ok || !data.user) {
        setError(data.error ?? 'Authentication failed.');
        return;
      }
      onAuthenticated(data.user);
    } catch {
      setError('Network error while contacting GatePulse auth server.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth/demo', { method: 'POST' });
      const data = (await res.json()) as { user?: User; error?: string };
      if (!res.ok || !data.user) {
        setError(data.error ?? 'Could not load demo workspace.');
        return;
      }
      onAuthenticated(data.user);
    } catch {
      setError('Network error while loading demo workspace.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F8F6F1] text-[#171614] flex flex-col">
      {/* 3-Zone Top Bar */}
      <header className="w-full border-b border-[#E4DFD3] bg-[#F8F6F1]">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
          <span className="text-lg font-bold tracking-tight text-[#171614] whitespace-nowrap shrink-0">
            GatePulse
          </span>
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-[#625F57]">
            <span className="whitespace-nowrap shrink-0">Security Gateway</span>
            <span className="whitespace-nowrap shrink-0">Webhook Dispatcher</span>
            <span className="whitespace-nowrap shrink-0">Anti-SSRF Registry</span>
            <span className="whitespace-nowrap shrink-0">Sandbox Tester</span>
          </nav>
          <button
            type="button"
            onClick={handleDemoLogin}
            disabled={loading}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Open Demo Console
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-12 grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
        {/* Left Feature Story Grid inspired by tactile pastel cards */}
        <div className="lg:col-span-7 space-y-6">
          <div className="space-y-3">
            <p className="text-xs font-medium text-[#625F57] tracking-wide">
              Developer-First Webhook & Event Ingestion
            </p>
            <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#171614] leading-[1.15] text-balance">
              Zero-trust API gateway and resilient webhook delivery for engineering teams.
            </h1>
            <p className="text-[15px] text-[#535049] leading-relaxed max-w-2xl">
              Ingest high-volume application events through a 6-layer security pipeline, isolate
              test and live traffic, and dispatch HMAC-signed webhooks with automatic retries.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <div className="rounded-xl border border-[#C5DEC8] bg-[#E8F5E9] p-5 space-y-2">
              <div className="flex items-center gap-2 text-[#165B29] font-semibold text-sm">
                <ShieldCheck className="w-4 h-4 shrink-0" />
                <span>6-Layer Entry Gateway</span>
              </div>
              <p className="text-xs text-[#2B4932] leading-relaxed">
                256 KB body cap, SHA-256 hashed API keys, sliding-window rate limits, HMAC
                anti-replay, and idempotency caching.
              </p>
            </div>

            <div className="rounded-xl border border-[#D4CCF3] bg-[#F1EEFC] p-5 space-y-2">
              <div className="flex items-center gap-2 text-[#3B267D] font-semibold text-sm">
                <KeyRound className="w-4 h-4 shrink-0" />
                <span>Prefixed Scoped Keys</span>
              </div>
              <p className="text-xs text-[#43366E] leading-relaxed">
                Separate <code className="font-mono">gp_test_</code> and{' '}
                <code className="font-mono">gp_live_</code> environments with one-time secret
                reveal and instant key rotation.
              </p>
            </div>

            <div className="rounded-xl border border-[#EED39C] bg-[#FDF4DC] p-5 space-y-2">
              <div className="flex items-center gap-2 text-[#6B460B] font-semibold text-sm">
                <Webhook className="w-4 h-4 shrink-0" />
                <span>Anti-SSRF Endpoint Guard</span>
              </div>
              <p className="text-xs text-[#61471A] leading-relaxed">
                DNS-verified target registry blocking loopback, private RFC1918 subnets, and
                cloud metadata endpoints.
              </p>
            </div>

            <div className="rounded-xl border border-[#C4DCF5] bg-[#EAF4FD] p-5 space-y-2">
              <div className="flex items-center gap-2 text-[#174678] font-semibold text-sm">
                <RefreshCw className="w-4 h-4 shrink-0" />
                <span>Async Queue & Replay</span>
              </div>
              <p className="text-xs text-[#294D73] leading-relaxed">
                Sub-50ms <code className="font-mono">202 Accepted</code> ingestion with exponential
                backoff retries and manual event replay.
              </p>
            </div>
          </div>
        </div>

        {/* Right Auth Card */}
        <div className="lg:col-span-5 bg-white border border-[#E4DFD3] rounded-xl p-6 sm:p-8">
          <div className="flex items-center justify-between border-b border-[#EFECE4] pb-4 mb-6">
            <div>
              <h2 className="text-lg font-bold text-[#171614]">
                {mode === 'login' ? 'Sign in to Console' : 'Create Developer Account'}
              </h2>
              <p className="text-xs text-[#625F57] mt-0.5">
                Multi-tenant project isolation with TEST & LIVE modes
              </p>
            </div>
          </div>

          <div className="flex gap-1 p-1 bg-[#F3EFE6] rounded-lg mb-5">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                mode === 'login'
                  ? 'bg-white text-[#171614] border border-[#E4DFD3]'
                  : 'text-[#625F57] hover:text-[#171614]'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                mode === 'register'
                  ? 'bg-white text-[#171614] border border-[#E4DFD3]'
                  : 'text-[#625F57] hover:text-[#171614]'
              }`}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'register' && (
              <div>
                <label
                  htmlFor="auth-name"
                  className="block text-xs font-medium text-[#3D3A34] mb-1.5"
                >
                  Full Name
                </label>
                <input
                  id="auth-name"
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Raka Wijaya"
                  className="w-full px-3 py-2 text-sm bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
                />
              </div>
            )}

            <div>
              <label
                htmlFor="auth-email"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                Developer Email
              </label>
              <input
                id="auth-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="dev@gatepulse.dev"
                className="w-full px-3 py-2 text-sm bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>

            <div>
              <label
                htmlFor="auth-password"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                Password
              </label>
              <input
                id="auth-password"
                type="password"
                required
                minLength={6}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Minimum 6 characters"
                className="w-full px-3 py-2 text-sm bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>

            {error && (
              <div
                role="alert"
                className="text-xs text-[#991B1B] bg-[#FEF2F2] border border-[#FECACA] rounded-lg px-3 py-2.5"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 text-sm font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] transition-colors flex items-center justify-center gap-2 cursor-pointer disabled:opacity-60"
            >
              <span>{mode === 'login' ? 'Sign In to Workspace' : 'Create Workspace'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-[#EFECE4] space-y-2.5">
            <button
              type="button"
              onClick={handleDemoLogin}
              disabled={loading}
              className="w-full py-2 px-4 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors cursor-pointer"
            >
              Continue as Demo Developer (dev@gatepulse.dev)
            </button>
            <p className="text-[11px] text-[#625F57] text-center">
              Demo workspace comes pre-populated with projects, endpoints, and gateway audit logs.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}
