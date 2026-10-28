import React from 'react';
import { useCrisp } from '../context/CrispContext';
import {
  LayoutDashboard,
  Radio,
  ShieldAlert,
  BrainCircuit,
  SlidersHorizontal,
  Shield,
  Layers,
  Sparkles,
} from 'lucide-react';

interface PrimaryNavItem {
  id: string;
  label: string;
  icon: React.ElementType;
  badge?: string;
  badgeVariant?: 'cyan' | 'indigo' | 'amber' | 'slate';
  description: string;
}

export const Sidebar: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    vulnerabilities,
    securityEvents,
    isDemoModeActive,
  } = useCrisp();

  // Exactly five primary navigation items as required by specification
  const PRIMARY_NAV_ITEMS: PrimaryNavItem[] = [
    {
      id: 'overview',
      label: 'Overview',
      icon: LayoutDashboard,
      description: 'Posture, risk score & metrics',
    },
    {
      id: 'live',
      label: 'Live Monitoring',
      icon: Radio,
      badge: isDemoModeActive ? 'SIM' : 'STREAM',
      badgeVariant: isDemoModeActive ? 'amber' : 'cyan',
      description: 'Real-time telemetry & simulation',
    },
    {
      id: 'intelligence',
      label: 'Security Intelligence',
      icon: ShieldAlert,
      badge: `${vulnerabilities.length}`,
      badgeVariant: 'slate',
      description: 'CVEs, KEV, findings & risk matrix',
    },
    {
      id: 'swarm',
      label: 'AI Swarm',
      icon: BrainCircuit,
      badge: 'LangGraph',
      badgeVariant: 'indigo',
      description: '7-agent autonomous investigations',
    },
    {
      id: 'admin',
      label: 'Data & Administration',
      icon: SlidersHorizontal,
      description: 'Sources, SQL inspector & sync',
    },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col shrink-0 min-h-[calc(100vh-3.5rem)] select-none">
      {/* Primary Navigation Section */}
      <div className="p-3">
        <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">
          Primary Operations
        </div>
        <nav className="space-y-1">
          {PRIMARY_NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-all text-left group ${
                  isActive
                    ? 'bg-slate-900 text-cyan-300 border border-cyan-800/60 shadow-sm shadow-cyan-950/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div
                    className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 transition-colors ${
                      isActive
                        ? 'bg-cyan-950 text-cyan-400 border border-cyan-800/80'
                        : 'bg-slate-900 text-slate-400 group-hover:text-slate-300 border border-slate-800'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="truncate">
                    <div className={`truncate leading-tight ${isActive ? 'text-white' : 'text-slate-300'}`}>
                      {item.label}
                    </div>
                    <div className="text-[10px] text-slate-400 font-normal truncate mt-0.5">
                      {item.description}
                    </div>
                  </div>
                </div>

                {item.badge && (
                  <span
                    className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase tracking-wider shrink-0 ml-1.5 ${
                      item.badgeVariant === 'indigo'
                        ? 'bg-indigo-950 text-indigo-300 border border-indigo-800/80'
                        : item.badgeVariant === 'amber'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800/80'
                        : item.badgeVariant === 'cyan'
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80'
                        : 'bg-slate-900 text-slate-400 border border-slate-800'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Operational Footprint & System Spec */}
      <div className="p-3 border-t border-slate-900/80 space-y-2">
        <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800/80 space-y-2 text-xs">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">Platform Core</span>
            <span className="text-cyan-400 font-mono font-bold">CRISP 2.0</span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">Supervised Multi-Agent</span>
            <span className="text-indigo-400 font-mono text-[10px]">7 Agents</span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">Local SQLite Engine</span>
            <span className="text-emerald-400 font-mono text-[10px]">WASM Active</span>
          </div>
        </div>

        <div className="text-[10px] text-slate-400 text-center font-mono">
          Strict 5-Option Architecture
        </div>
      </div>
    </aside>
  );
};
