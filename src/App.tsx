/**
 * CRISP - Cyber Risk Intelligence & Security Posture
 * Executive Multi-Agent Cybersecurity Operations Platform
 */

import React from 'react';
import { CrispProvider, useCrisp } from './context/CrispContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { LiveMonitoringView } from './views/LiveMonitoringView';
import { SecurityIntelligenceView } from './views/SecurityIntelligenceView';
import { AgentSwarmView } from './views/AgentSwarmView';
import { DataAdminView } from './views/DataAdminView';
import { Shield, RefreshCw, AlertTriangle } from 'lucide-react';

const MainContent: React.FC = () => {
  const {
    activeTab,
    isInitialized,
    initStage,
    initPercent,
    initError,
    retryInit,
  } = useCrisp();

  // Non-blocking initialization: shell remains visible with compact progress bar
  if (!isInitialized) {
    const isError = Boolean(initError);

    return (
      <main className="flex-1 p-6 lg:p-8 bg-slate-950 text-slate-100 overflow-y-auto flex flex-col justify-center items-center min-h-[calc(100vh-3.5rem)]">
        <div className="w-full max-w-lg p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl text-center space-y-4">
          <div
            className={`w-12 h-12 rounded-xl flex items-center justify-center shadow-lg mx-auto text-white ${
              isError
                ? 'bg-rose-600 shadow-rose-600/30'
                : 'bg-gradient-to-tr from-cyan-500 to-blue-600 shadow-cyan-500/20'
            }`}
          >
            {isError ? (
              <AlertTriangle className="w-6 h-6 text-white" />
            ) : (
              <Shield className="w-6 h-6 animate-pulse" />
            )}
          </div>

          <div>
            <h2 className="text-base font-bold text-white tracking-tight">
              {isError ? 'Platform Initialization Interrupted' : 'Initializing CRISP Platform'}
            </h2>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              {isError ? 'An operational failure occurred during startup.' : initStage || 'Loading WebAssembly database and security baselines...'}
            </p>
          </div>

          {!isError ? (
            <>
              {/* Compact Progress Bar */}
              <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                <div
                  className="bg-cyan-500 h-full rounded-full transition-all duration-300"
                  style={{ width: `${Math.min(100, Math.max(10, initPercent))}%` }}
                />
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                <span>Stage: {initPercent}%</span>
                <div className="flex items-center gap-1.5 text-cyan-400">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Hydrating</span>
                </div>
              </div>
            </>
          ) : (
            (() => {
              const errText = initError || 'Unknown startup error';
              const errCode = errText.includes('CRISP-ERR') ? errText.split(':')[0] : 'ERR_STARTUP';
              const errDesc = errText.replace(/^CRISP-ERR-[A-Z0-9-]+:\s*/, '');
              const errScope = errText.includes('WASM')
                ? 'Local WebAssembly SQLite runtime'
                : 'Data pipeline / ingestion';

              return (
                <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-left space-y-3">
                  <div className="flex items-center justify-between border-b border-rose-900/50 pb-2">
                    <span className="text-xs font-semibold text-rose-300">Diagnostic Details</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-900/60 text-rose-200 border border-rose-700/50">
                      {errCode}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-xs text-slate-300">
                    <div className="flex items-start gap-2">
                      <span className="text-slate-500 font-mono text-[11px] w-20 shrink-0">Stage:</span>
                      <span className="font-mono text-[11px] text-slate-200">{initStage || 'Database initialization'}</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-slate-500 font-mono text-[11px] w-20 shrink-0">Message:</span>
                      <span className="text-[11px] text-rose-300 break-words font-mono">
                        {errDesc}
                      </span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-slate-500 font-mono text-[11px] w-20 shrink-0">Scope:</span>
                      <span className="text-[11px] text-slate-300">{errScope}</span>
                    </div>
                  </div>

                  <button
                    onClick={retryInit}
                    className="w-full mt-2 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-2 shadow-lg shadow-rose-900/40"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Retry Initialization</span>
                  </button>
                </div>
              );
            })()
          )}
        </div>
      </main>
    );
  }

  return (
    <main className="flex-1 p-4 sm:p-6 lg:p-8 bg-slate-950 text-slate-100 overflow-y-auto">
      <div className="max-w-7xl mx-auto">
        {/* Exactly 5 Primary Views */}
        {(activeTab === 'overview' || activeTab === 'dashboard') && <OverviewView />}
        {(activeTab === 'live' || activeTab === 'events') && <LiveMonitoringView />}
        {(activeTab === 'intelligence' ||
          activeTab === 'vulnerabilities' ||
          activeTab === 'findings' ||
          activeTab === 'risk' ||
          activeTab === 'compliance' ||
          activeTab === 'assets' ||
          activeTab === 'cisa_kev' ||
          activeTab === 'remediation') && <SecurityIntelligenceView />}
        {(activeTab === 'swarm' || activeTab === 'agents') && <AgentSwarmView />}
        {(activeTab === 'admin' ||
          activeTab === 'datasources' ||
          activeTab === 'importer' ||
          activeTab === 'sqlite') && <DataAdminView />}
      </div>
    </main>
  );
};

export default function App() {
  return (
    <CrispProvider>
      <div className="min-h-screen bg-slate-950 flex flex-col font-sans selection:bg-cyan-500 selection:text-white">
        <Navbar />
        <div className="flex flex-1">
          <Sidebar />
          <MainContent />
        </div>
      </div>
    </CrispProvider>
  );
}
