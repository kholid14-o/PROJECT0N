import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  BookOpen,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Plus,
  Terminal,
  Webhook,
  X,
} from 'lucide-react';
import type {
  ApiKeyItem,
  ConsoleTab,
  Environment,
  EventItem,
  GatewayLogItem,
  GatewayMetrics,
  Project,
  User,
  WebhookEndpointItem,
} from './types';
import { AuthScreen } from './components/AuthScreen';
import { OverviewView } from './components/OverviewView';
import { ApiKeysView } from './components/ApiKeysView';
import { EndpointsView } from './components/EndpointsView';
import { EventsInspectorView } from './components/EventsInspectorView';
import { PlaygroundView } from './components/PlaygroundView';
import { ErrorDocsView } from './components/ErrorDocsView';

const TAB_LABELS: Record<ConsoleTab, string> = {
  overview: 'Overview',
  keys: 'API Keys',
  endpoints: 'Webhook Endpoints',
  events: 'Events & Logs',
  playground: 'API Playground',
  errors: 'Error Reference',
};

const DEFAULT_METRICS: GatewayMetrics = {
  events_ingested: 0,
  active_keys: 0,
  active_endpoints: 0,
  blocked_requests: 0,
  deliveries: { success: 0, failed: 0, pending: 0 },
};

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authChecked, setAuthChecked] = useState(false);

  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProjectId, setActiveProjectId] = useState<string>('');
  const [environment, setEnvironment] = useState<Environment>('test');
  const [activeTab, setActiveTab] = useState<ConsoleTab>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [endpoints, setEndpoints] = useState<WebhookEndpointItem[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [gatewayLogs, setGatewayLogs] = useState<GatewayLogItem[]>([]);
  const [metrics, setMetrics] = useState<GatewayMetrics>(DEFAULT_METRICS);

  const [playgroundKey, setPlaygroundKey] = useState('');

  const [showNewProject, setShowNewProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectLimit, setNewProjectLimit] = useState('60');
  const [projectError, setProjectError] = useState<string | null>(null);

  const loadSession = useCallback(async () => {
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get('autostart') === '1') {
        await fetch('/api/auth/demo', { method: 'POST' });
      }
      const res = await fetch('/api/auth/me');
      if (res.ok) {
        const data = (await res.json()) as { user: User | null };
        setUser(data.user);
      } else {
        setUser(null);
      }
    } finally {
      setAuthChecked(true);
    }
  }, []);

  useEffect(() => {
    if (window.location.pathname.startsWith('/docs/errors')) {
      setActiveTab('errors');
    }
    void loadSession();
  }, [loadSession]);

  const loadProjects = useCallback(async () => {
    if (!user) return;
    const res = await fetch('/api/projects');
    if (!res.ok) return;
    const data = (await res.json()) as { projects: Project[] };
    setProjects(data.projects);
    if (data.projects.length > 0) {
      setActiveProjectId((prev) =>
        data.projects.some((p) => p.id === prev) ? prev : data.projects[0].id
      );
    }
  }, [user]);

  useEffect(() => {
    void loadProjects();
  }, [loadProjects]);

  const loadProjectData = useCallback(async () => {
    if (!user || !activeProjectId) return;
    const query = `environment=${environment}`;
    const [keysRes, epRes, evtRes, logsRes] = await Promise.all([
      fetch(`/api/projects/${activeProjectId}/api-keys?${query}`),
      fetch(`/api/projects/${activeProjectId}/endpoints?${query}`),
      fetch(`/api/projects/${activeProjectId}/events?${query}`),
      fetch(`/api/projects/${activeProjectId}/gateway-logs?${query}`),
    ]);

    if (keysRes.ok) {
      const d = (await keysRes.json()) as { api_keys: ApiKeyItem[] };
      setApiKeys(d.api_keys);
    }
    if (epRes.ok) {
      const d = (await epRes.json()) as { endpoints: WebhookEndpointItem[] };
      setEndpoints(d.endpoints);
    }
    if (evtRes.ok) {
      const d = (await evtRes.json()) as { events: EventItem[] };
      setEvents(d.events);
    }
    if (logsRes.ok) {
      const d = (await logsRes.json()) as {
        logs: GatewayLogItem[];
        metrics: GatewayMetrics;
      };
      setGatewayLogs(d.logs);
      setMetrics(d.metrics);
    }
  }, [user, activeProjectId, environment]);

  useEffect(() => {
    void loadProjectData();
  }, [loadProjectData]);

  const activeProject = projects.find((p) => p.id === activeProjectId) ?? null;

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    setUser(null);
    setProjects([]);
    setActiveProjectId('');
    setPlaygroundKey('');
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    setProjectError(null);
    const res = await fetch('/api/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: newProjectName,
        rate_limit_per_minute: Number.parseInt(newProjectLimit, 10) || 60,
      }),
    });
    const data = (await res.json()) as { project?: Project; error?: string };
    if (!res.ok || !data.project) {
      setProjectError(data.error ?? 'Could not create project.');
      return;
    }
    setProjects((prev) => [...prev, data.project!]);
    setActiveProjectId(data.project.id);
    setNewProjectName('');
    setShowNewProject(false);
  };

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-[#F8F6F1] flex items-center justify-center text-sm text-[#625F57]">
        Loading GatePulse console...
      </div>
    );
  }

  if (!user) {
    return <AuthScreen onAuthenticated={(u) => setUser(u)} />;
  }

  const navItems: Array<{ id: ConsoleTab; label: string; icon: React.ReactNode }> = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'keys', label: 'API Keys', icon: <KeyRound className="w-4 h-4" /> },
    { id: 'endpoints', label: 'Webhook Endpoints', icon: <Webhook className="w-4 h-4" /> },
    { id: 'events', label: 'Events & Logs', icon: <Activity className="w-4 h-4" /> },
    { id: 'playground', label: 'API Playground', icon: <Terminal className="w-4 h-4" /> },
    { id: 'errors', label: 'Error Reference', icon: <BookOpen className="w-4 h-4" /> },
  ];

  const sidebarContent = (
    <div className="h-full flex flex-col bg-[#F3EFE6] border-r border-[#E4DFD3]">
      <div className="h-16 px-5 border-b border-[#E4DFD3] flex items-center justify-between">
        <span className="text-lg font-extrabold tracking-tight text-[#171614] whitespace-nowrap">
          GatePulse
        </span>
        <button
          type="button"
          onClick={() => setMobileMenuOpen(false)}
          aria-label="Close navigation menu"
          className="lg:hidden p-1 text-[#625F57] hover:text-[#171614]"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-4 border-b border-[#E4DFD3]">
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="project-select" className="text-[11px] font-semibold text-[#625F57]">
              Project Workspace
            </label>
            <button
              type="button"
              onClick={() => {
                setShowNewProject(true);
                setProjectError(null);
              }}
              className="text-[11px] font-semibold text-[#171614] hover:underline inline-flex items-center gap-0.5 cursor-pointer"
            >
              <Plus className="w-3 h-3" />
              <span>New</span>
            </button>
          </div>
          <select
            id="project-select"
            value={activeProjectId}
            onChange={(e) => {
              setActiveProjectId(e.target.value);
              setPlaygroundKey('');
            }}
            className="w-full px-2.5 py-2 text-xs font-semibold bg-white border border-[#DCD6C8] rounded-lg text-[#171614] cursor-pointer"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>

        {/* TEST / LIVE Environment Switcher */}
        <div>
          <span className="block text-[11px] font-semibold text-[#625F57] mb-1.5">
            Environment Mode
          </span>
          <div
            role="group"
            aria-label="Environment selector"
            className="grid grid-cols-2 gap-1 p-1 bg-[#E7E1D4] rounded-lg"
          >
            <button
              type="button"
              onClick={() => setEnvironment('test')}
              className={`py-1.5 text-xs font-bold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                environment === 'test'
                  ? 'bg-[#FEF3C7] text-[#92400E] border border-[#F59E0B]/40'
                  : 'text-[#625F57] hover:text-[#171614]'
              }`}
            >
              TEST Mode
            </button>
            <button
              type="button"
              onClick={() => setEnvironment('live')}
              className={`py-1.5 text-xs font-bold rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                environment === 'live'
                  ? 'bg-[#DCFCE7] text-[#166534] border border-[#16A34A]/40'
                  : 'text-[#625F57] hover:text-[#171614]'
              }`}
            >
              LIVE Mode
            </button>
          </div>
        </div>
      </div>

      <nav aria-label="Console navigation" className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setActiveTab(item.id);
                setMobileMenuOpen(false);
              }}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'bg-white text-[#171614] border border-[#E4DFD3]'
                  : 'text-[#535049] hover:bg-white/60 hover:text-[#171614]'
              }`}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-[#E4DFD3] flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-xs font-semibold text-[#171614] truncate">{user.name}</p>
          <p className="text-[11px] text-[#625F57] truncate">{user.email}</p>
        </div>
        <button
          type="button"
          onClick={handleLogout}
          aria-label="Sign out"
          title="Sign out"
          className="p-2 rounded-lg border border-[#DCD6C8] bg-white hover:bg-[#FAF9F6] text-[#171614] shrink-0 cursor-pointer"
        >
          <LogOut className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-[#F8F6F1] text-[#171614] flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:block w-64 shrink-0 sticky top-0 h-screen">
        {sidebarContent}
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="w-72 h-full">{sidebarContent}</div>
          <button
            type="button"
            aria-label="Dismiss menu backdrop"
            onClick={() => setMobileMenuOpen(false)}
            className="flex-1 bg-black/35"
          />
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-16 px-4 sm:px-8 border-b border-[#E4DFD3] bg-[#F8F6F1] flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden p-2 rounded-lg border border-[#DCD6C8] bg-white text-[#171614]"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-xs sm:text-sm truncate">
              <span className="font-semibold text-[#625F57] truncate">
                {activeProject?.name ?? 'Workspace'}
              </span>
              <span className="text-[#9E998E]" aria-hidden="true">
                /
              </span>
              <span className="font-bold text-[#171614] whitespace-nowrap">
                {TAB_LABELS[activeTab]}
              </span>
              <span className="text-[#9E998E] hidden sm:inline" aria-hidden="true">
                ·
              </span>
              <span
                className={`hidden sm:inline font-mono text-xs font-bold whitespace-nowrap ${
                  environment === 'live' ? 'text-[#15803D]' : 'text-[#B45309]'
                }`}
              >
                {environment.toUpperCase()}
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setActiveTab(activeTab === 'playground' ? 'events' : 'playground')}
            className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-[#F2A379] text-[#171614] border border-[#DF8B5E] hover:bg-[#EDA074] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {activeTab === 'playground' ? 'Inspect Events' : 'API Playground'}
          </button>
        </header>

        <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-8 py-6 sm:py-8">
          {!activeProject ? (
            <div className="bg-white border border-[#E4DFD3] rounded-xl p-10 text-center space-y-3">
              <p className="text-sm font-semibold text-[#171614]">No project workspace yet</p>
              <button
                type="button"
                onClick={() => setShowNewProject(true)}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#171614] text-white cursor-pointer"
              >
                Create First Project
              </button>
            </div>
          ) : (
            <>
              {activeTab === 'overview' && (
                <OverviewView
                  project={activeProject}
                  environment={environment}
                  metrics={metrics}
                  gatewayLogs={gatewayLogs}
                  onProjectUpdated={(updated) => {
                    setProjects((prev) =>
                      prev.map((p) => (p.id === updated.id ? updated : p))
                    );
                  }}
                  onNavigate={setActiveTab}
                />
              )}

              {activeTab === 'keys' && (
                <ApiKeysView
                  projectId={activeProject.id}
                  environment={environment}
                  apiKeys={apiKeys}
                  onRefresh={loadProjectData}
                  onUseInPlayground={(rawKey) => {
                    setPlaygroundKey(rawKey);
                    setActiveTab('playground');
                  }}
                />
              )}

              {activeTab === 'endpoints' && (
                <EndpointsView
                  projectId={activeProject.id}
                  environment={environment}
                  endpoints={endpoints}
                  onRefresh={loadProjectData}
                />
              )}

              {activeTab === 'events' && (
                <EventsInspectorView
                  projectId={activeProject.id}
                  environment={environment}
                  events={events}
                  gatewayLogs={gatewayLogs}
                  onRefresh={loadProjectData}
                />
              )}

              {activeTab === 'playground' && (
                <PlaygroundView
                  project={activeProject}
                  environment={environment}
                  initialApiKey={playgroundKey}
                  onApiKeyChange={setPlaygroundKey}
                  onEventSent={loadProjectData}
                />
              )}

              {activeTab === 'errors' && <ErrorDocsView />}
            </>
          )}
        </main>
      </div>

      {/* Create New Project Modal */}
      {showNewProject && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="new-project-title"
          className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4"
        >
          <form
            onSubmit={handleCreateProject}
            className="bg-white border border-[#E4DFD3] rounded-xl max-w-md w-full p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-[#EFECE4] pb-3">
              <h3 id="new-project-title" className="text-base font-bold text-[#171614]">
                Create New Project Workspace
              </h3>
              <button
                type="button"
                onClick={() => setShowNewProject(false)}
                aria-label="Close new project modal"
                className="p-1 text-[#625F57] hover:text-[#171614] cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <label
                htmlFor="new-proj-name"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                Project Name
              </label>
              <input
                id="new-proj-name"
                type="text"
                required
                value={newProjectName}
                onChange={(e) => setNewProjectName(e.target.value)}
                placeholder="e.g. Fintech Ledger Service"
                className="w-full px-3 py-2 text-sm bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>

            <div>
              <label
                htmlFor="new-proj-limit"
                className="block text-xs font-medium text-[#3D3A34] mb-1.5"
              >
                Rate Limit (req / min)
              </label>
              <input
                id="new-proj-limit"
                type="number"
                min={1}
                max={10000}
                value={newProjectLimit}
                onChange={(e) => setNewProjectLimit(e.target.value)}
                className="w-full px-3 py-2 text-sm font-mono bg-[#FAF9F6] border border-[#DCD6C8] rounded-lg focus:outline-none focus:border-[#171614]"
              />
            </div>

            {projectError && (
              <div className="text-xs text-[#991B1B] bg-[#FEF2F2] border border-[#FECACA] rounded-lg px-3 py-2">
                {projectError}
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-[#EFECE4]">
              <button
                type="button"
                onClick={() => setShowNewProject(false)}
                className="px-3.5 py-2 text-xs font-medium text-[#625F57] hover:text-[#171614] cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#171614] text-white hover:bg-[#2C2A26] cursor-pointer"
              >
                Create Project
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
