import React from 'react';
import { useCrisp } from '../context/CrispContext';
import {
  Shield,
  RefreshCw,
  Radio,
  Zap,
  Clock,
  Sparkles,
  SlidersHorizontal,
} from 'lucide-react';
import { DataSourceBadge } from './DataSourceBadge';

export const Navbar: React.FC = () => {
  const {
    lastDataUpdate,
    isSyncing,
    refreshIntelligence,
    isDemoModeActive,
    toggleDemoMode,
    simulateSingleEvent,
    provenanceFilter,
    setProvenanceFilter,
  } = useCrisp();

  return (
    <header className="border-b border-slate-800 bg-slate-900/95 sticky top-0 z-40 backdrop-blur-md">
      {/* Top Banner with Platform Branding and Provenance Status */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Name */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white font-bold">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-tight text-white">CRISP</span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                  v2.2 Real-Data SOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Cyber Risk Intelligence &amp; Scoring Platform
              </p>
            </div>
          </div>

          {/* Center: Visible Timestamps and Data Source Indicators */}
          <div className="hidden xl:flex items-center gap-4 bg-slate-950/80 px-4 py-1.5 rounded-lg border border-slate-800 text-xs">
            <div className="flex items-center gap-1.5 text-slate-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-400 font-medium">Last data update:</span>
              <span className="font-mono text-cyan-300 font-semibold">{lastDataUpdate}</span>
            </div>
            <div className="h-4 w-px bg-slate-800"></div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Active Feeds:</span>
              <DataSourceBadge origin="NVD_API" size="sm" />
              <DataSourceBadge origin="CISA_KEV" size="sm" />
              <DataSourceBadge origin="SYNTHETIC_DEMO" size="sm" />
            </div>
          </div>

          {/* Right Action Controls */}
          <div className="flex items-center gap-2.5">
            {/* Provenance Filter */}
            <div className="hidden md:flex items-center gap-1 bg-slate-950/60 p-1 rounded-lg border border-slate-800 text-xs">
              <SlidersHorizontal className="w-3.5 h-3.5 text-slate-400 ml-1.5 mr-1" />
              <button
                onClick={() => setProvenanceFilter('ALL')}
                className={`px-2 py-1 rounded font-medium transition-colors ${
                  provenanceFilter === 'ALL'
                    ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                All Records
              </button>
              <button
                onClick={() => setProvenanceFilter('REAL_ONLY')}
                className={`px-2 py-1 rounded font-medium transition-colors ${
                  provenanceFilter === 'REAL_ONLY'
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Real Only
              </button>
              <button
                onClick={() => setProvenanceFilter('SYNTHETIC_ONLY')}
                className={`px-2 py-1 rounded font-medium transition-colors ${
                  provenanceFilter === 'SYNTHETIC_ONLY'
                    ? 'bg-purple-950 text-purple-300 border border-purple-800'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Demo Only
              </button>
            </div>

            {/* Refresh Intelligence Button */}
            <button
              onClick={() => refreshIntelligence(true)}
              disabled={isSyncing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold shadow-xs transition-colors disabled:opacity-50"
              title="Queries live NVD API 2.0 and CISA KEV catalog, normalizes, validates, and commits to SQLite"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin text-cyan-400' : ''}`} />
              <span className="hidden sm:inline">Refresh Intelligence</span>
            </button>

            {/* Simulate Incident Button */}
            <button
              onClick={simulateSingleEvent}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-900/60 hover:bg-purple-800/80 text-purple-200 border border-purple-700/60 text-xs font-semibold shadow-xs transition-colors"
              title="Simulates an incoming security event for demonstration purposes"
            >
              <Zap className="w-3.5 h-3.5 text-purple-400" />
              <span className="hidden md:inline">Simulate Event</span>
            </button>

            {/* Live Streaming Toggle */}
            <button
              onClick={toggleDemoMode}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold shadow-xs transition-colors ${
                isDemoModeActive
                  ? 'bg-rose-950/70 border-rose-600/70 text-rose-300 animate-pulse'
                  : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
              }`}
              title="Starts automated continuous event stream for live project demo"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>{isDemoModeActive ? 'Streaming Active' : 'Start Demo Stream'}</span>
            </button>
          </div>
        </div>

        {/* Mobile / Tablet sub-bar for timestamps */}
        <div className="xl:hidden flex flex-wrap items-center justify-between py-2 border-t border-slate-800/60 text-[11px] text-slate-400">
          <div className="flex items-center gap-1.5">
            <Clock className="w-3 h-3 text-cyan-400" />
            <span>Last data update:</span>
            <span className="font-mono text-cyan-300 font-semibold">{lastDataUpdate}</span>
          </div>
          <div className="flex items-center gap-2">
            <DataSourceBadge origin="NVD_API" size="sm" />
            <DataSourceBadge origin="CISA_KEV" size="sm" />
            <DataSourceBadge origin="SYNTHETIC_DEMO" size="sm" />
          </div>
        </div>
      </div>
    </header>
  );
};
