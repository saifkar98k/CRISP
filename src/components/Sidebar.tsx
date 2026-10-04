import React from 'react';
import { useCrisp } from '../context/CrispContext';
import {
  LayoutDashboard,
  Radio,
  ShieldAlert,
  Activity,
  Calculator,
  Award,
  Database,
  FileSpreadsheet,
  Terminal,
  Trash2,
  Sliders,
  CheckCircle,
  ExternalLink,
  GitMerge,
} from 'lucide-react';

interface NavItem {
  id: string;
  label: string;
  icon: React.ElementType;
  badge?: string;
  badgeColor?: string;
}

export const Sidebar: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    vulnerabilities,
    securityEvents,
    isDemoModeActive,
    toggleDemoMode,
    demoStreamSpeed,
    setDemoStreamSpeed,
    clearSyntheticEvents,
  } = useCrisp();

  const realVulnCount = vulnerabilities.filter((v) => v.isRealData).length;
  const realEventCount = securityEvents.filter((e) => e.isRealData).length;
  const demoEventCount = securityEvents.filter((e) => !e.isRealData).length;

  const NAV_ITEMS: NavItem[] = [
    {
      id: 'live',
      label: 'Live Monitoring',
      icon: Radio,
      badge: 'SIMULATOR',
      badgeColor: 'bg-amber-950/80 text-amber-300 border border-amber-800 animate-pulse',
    },
    {
      id: 'dashboard',
      label: 'Executive Dashboard',
      icon: LayoutDashboard,
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerability Intelligence',
      icon: ShieldAlert,
      badge: `${realVulnCount} CVEs`,
      badgeColor: 'bg-emerald-950 text-emerald-400 border border-emerald-800',
    },
    {
      id: 'events',
      label: 'Security Incidents & Events',
      icon: Activity,
      badge: `${securityEvents.length}`,
      badgeColor: 'bg-sky-950 text-sky-400 border border-sky-800',
    },
    {
      id: 'findings',
      label: 'Correlated Findings',
      icon: GitMerge,
      badge: 'Unified',
      badgeColor: 'bg-cyan-950 text-cyan-400 border border-cyan-800',
    },
    {
      id: 'risk',
      label: 'Cyber Risk Matrix & Engine',
      icon: Calculator,
    },
    {
      id: 'compliance',
      label: 'NIST CSF 2.0 Compliance',
      icon: Award,
    },
    {
      id: 'datasources',
      label: 'Data Sources & Integrity',
      icon: Database,
      badge: 'Live Status',
      badgeColor: 'bg-amber-950 text-amber-400 border border-amber-800',
    },
    {
      id: 'importer',
      label: 'CSV Importer & Mapping',
      icon: FileSpreadsheet,
    },
    {
      id: 'sqlite',
      label: 'SQLite Database Inspector',
      icon: Terminal,
    },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col shrink-0 min-h-[calc(100vh-4rem)]">
      {/* Navigation Links */}
      <nav className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">
          Operational Views
        </div>

        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-700/50 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-medium ${item.badgeColor || 'bg-slate-800 text-slate-300'}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Streamlit-style Sidebar Controls Widget */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/80 space-y-4">
        {/* Academic Demo Controls */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-purple-400" /> Demo Simulator
            </span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800">
              {demoEventCount} Mock Evts
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Streaming Speed:</span>
              <select
                value={demoStreamSpeed}
                onChange={(e) => setDemoStreamSpeed(Number(e.target.value))}
                className="bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-slate-300 text-xs font-mono"
              >
                <option value={1500}>1.5 sec (Fast)</option>
                <option value={3500}>3.5 sec (Normal)</option>
                <option value={6000}>6.0 sec (Slow)</option>
              </select>
            </div>

            <div className="flex gap-1.5">
              <button
                onClick={toggleDemoMode}
                className={`flex-1 py-1 rounded text-xs font-semibold transition-colors ${
                  isDemoModeActive
                    ? 'bg-rose-900/60 hover:bg-rose-800 text-rose-200 border border-rose-700'
                    : 'bg-purple-900/60 hover:bg-purple-800 text-purple-200 border border-purple-700'
                }`}
              >
                {isDemoModeActive ? 'Stop Stream' : 'Start Stream'}
              </button>
              {demoEventCount > 0 && (
                <button
                  onClick={clearSyntheticEvents}
                  title="Purge only synthetic events from SQLite"
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-rose-400 border border-slate-700 text-xs transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Database Integrity Badge */}
        <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 text-[11px] text-slate-400 space-y-1">
          <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
            <CheckCircle className="w-3.5 h-3.5" /> SQLite WASM Engine
          </div>
          <p className="text-[10px] text-slate-400">
            Real relational storage with normalized tables and SQL indexes.
          </p>
        </div>
      </div>
    </aside>
  );
};
