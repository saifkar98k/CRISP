/**
 * CRISP - Cyber Risk Intelligence & Scoring Platform
 * Executive Cybersecurity Operations Platform
 */

import React from 'react';
import { CrispProvider, useCrisp } from './context/CrispContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { DashboardView } from './views/DashboardView';
import { VulnerabilitiesView } from './views/VulnerabilitiesView';
import { SecurityEventsView } from './views/SecurityEventsView';
import { RiskMatrixView } from './views/RiskMatrixView';
import { ComplianceView } from './views/ComplianceView';
import { DataSourcesView } from './views/DataSourcesView';
import { DataImporterView } from './views/DataImporterView';
import { CorrelatedFindingsView } from './views/CorrelatedFindingsView';
import { LiveMonitoringView } from './views/LiveMonitoringView';
import { SQLQueryInspector } from './components/SQLQueryInspector';
import { Shield, RefreshCw } from 'lucide-react';

const MainContent: React.FC = () => {
  const { activeTab, isInitialized } = useCrisp();

  if (!isInitialized) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-slate-950 min-h-[calc(100vh-4rem)]">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-xl shadow-cyan-500/20 mb-4 animate-pulse">
          <Shield className="w-8 h-8 text-white" />
        </div>
        <h2 className="text-lg font-bold text-white mb-2">Initializing CRISP Platform</h2>
        <p className="text-xs text-slate-400 max-w-sm mb-4">
          Bootstrapping WebAssembly SQLite database engine, loading normalized schemas, and hydrating vulnerability intelligence...
        </p>
        <div className="flex items-center gap-2 text-xs text-cyan-400 font-mono">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span>Executing Data Pipeline...</span>
        </div>
      </div>
    );
  }

  return (
    <main className="flex-1 p-4 sm:p-6 lg:p-8 bg-slate-950 text-slate-100 overflow-y-auto">
      <div className="max-w-7xl mx-auto">
        {activeTab === 'live' && <LiveMonitoringView />}
        {activeTab === 'dashboard' && <DashboardView />}
        {activeTab === 'vulnerabilities' && <VulnerabilitiesView />}
        {activeTab === 'events' && <SecurityEventsView />}
        {activeTab === 'findings' && <CorrelatedFindingsView />}
        {activeTab === 'risk' && <RiskMatrixView />}
        {activeTab === 'compliance' && <ComplianceView />}
        {activeTab === 'datasources' && <DataSourcesView />}
        {activeTab === 'importer' && <DataImporterView />}
        {activeTab === 'sqlite' && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">Direct SQLite Database Inspector</h2>
              <p className="text-xs text-slate-400 mt-1">
                Execute arbitrary SQL queries against the local embedded WebAssembly SQLite database.
              </p>
            </div>
            <SQLQueryInspector />
          </div>
        )}
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
