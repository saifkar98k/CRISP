import React, { useState } from 'react';
import { useCrisp } from '../context/CrispContext';
import {
  Shield,
  Activity,
  Bell,
  Clock,
  User,
  CheckCircle2,
  ChevronDown,
  AlertTriangle,
  Flame,
  Radio,
} from 'lucide-react';
import { AuthModal } from './AuthModal';

export const Navbar: React.FC = () => {
  const {
    lastDataUpdate,
    vulnerabilities,
    securityEvents,
    setActiveTab,
    isDemoModeActive,
  } = useCrisp();

  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [isAlertsOpen, setIsAlertsOpen] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);

  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const stored = localStorage.getItem('crisp_user');
      if (stored) return JSON.parse(stored);
    } catch (e) {}
    return {
      email: 'saifkar98k@gmail.com',
      username: 'saifkar98k',
      role: 'SECURITY_ANALYST',
      tenant_id: 'default_tenant',
    };
  });

  const handleUserChanged = (newUser: any) => {
    setCurrentUser(newUser);
  };

  // Critical alerts calculation
  const criticalEvents = securityEvents.filter((e) => e.severity === 'CRITICAL');
  const criticalVulns = vulnerabilities.filter((v) => v.cvssScore >= 9.0 || v.isKnownExploited);
  const totalCriticalAlerts = criticalEvents.length + criticalVulns.length;

  return (
    <header className="border-b border-slate-800 bg-slate-950/95 sticky top-0 z-40 backdrop-blur-md">
      <div className="w-full px-4 sm:px-6">
        <div className="flex items-center justify-between h-14">
          {/* Left: CRISP Logo & Product Identity */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-md shadow-cyan-500/20 text-white font-bold shrink-0">
              <Shield className="w-4.5 h-4.5" />
            </div>
            <div className="flex items-center gap-2.5">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-extrabold text-sm tracking-tight text-white">CRISP</span>
                  <span className="text-[11px] font-semibold text-slate-300 hidden md:inline">
                    Cyber Risk Intelligence &amp; Security Posture
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                    v2.2
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Center-Right: Environment, Health, Data Freshness, Alerts, Profile */}
          <div className="flex items-center gap-3">
            {/* Environment Badge */}
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs">
              <span className={`w-1.5 h-1.5 rounded-full ${isDemoModeActive ? 'bg-amber-400' : 'bg-emerald-400'}`} />
              <span className="text-slate-400 text-[11px] font-medium uppercase tracking-wider">Env:</span>
              <span className="font-mono text-[11px] font-semibold text-slate-200">
                {isDemoModeActive ? 'DEMO / SIM' : 'PRODUCTION'}
              </span>
            </div>

            {/* Overall System Health Indicator */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-slate-300 text-[11px] font-medium hidden md:inline">System:</span>
              <span className="text-emerald-300 text-[11px] font-semibold">Operational</span>
            </div>

            {/* Concise Data Freshness Indicator */}
            <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs text-slate-400">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-[11px]">Sync:</span>
              <span className="font-mono text-[11px] text-cyan-300 font-medium">
                {lastDataUpdate.includes('T') ? lastDataUpdate.split('T')[1]?.substring(0, 8) || lastDataUpdate : lastDataUpdate}
              </span>
            </div>

            {/* Notification / Alert Indicator */}
            <div className="relative">
              <button
                onClick={() => setIsAlertsOpen(!isAlertsOpen)}
                className="relative p-1.5 rounded-md bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs transition-colors"
                title={`${totalCriticalAlerts} active critical alerts`}
              >
                <Bell className="w-4 h-4 text-slate-300" />
                {totalCriticalAlerts > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-600 text-[9px] font-mono font-bold text-white flex items-center justify-center ring-2 ring-slate-950">
                    {totalCriticalAlerts > 9 ? '9+' : totalCriticalAlerts}
                  </span>
                )}
              </button>

              {/* Alert Popover */}
              {isAlertsOpen && (
                <div className="absolute right-0 mt-2 w-80 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-3 z-50 text-xs font-sans">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <span className="font-bold text-white flex items-center gap-1.5">
                      <Flame className="w-3.5 h-3.5 text-rose-400" />
                      Active Security Alerts
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      {totalCriticalAlerts} pending
                    </span>
                  </div>
                  <div className="py-2 space-y-2 max-h-60 overflow-y-auto">
                    {criticalEvents.slice(0, 3).map((evt) => (
                      <div
                        key={evt.id}
                        onClick={() => {
                          setActiveTab('live');
                          setIsAlertsOpen(false);
                        }}
                        className="p-2 rounded bg-rose-950/40 border border-rose-900/60 cursor-pointer hover:bg-rose-950/70 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-rose-300 text-[11px]">{evt.attackCategory}</span>
                          <span className="text-[9px] font-mono text-slate-400">{evt.timestamp.split('T')[1]?.substring(0, 5) || ''}</span>
                        </div>
                        <p className="text-[10px] text-slate-300 truncate mt-0.5">{evt.description}</p>
                      </div>
                    ))}
                    {criticalVulns.slice(0, 2).map((vuln) => (
                      <div
                        key={vuln.id}
                        onClick={() => {
                          setActiveTab('intelligence');
                          setIsAlertsOpen(false);
                        }}
                        className="p-2 rounded bg-amber-950/40 border border-amber-900/60 cursor-pointer hover:bg-amber-950/70 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-amber-300 text-[11px]">{vuln.id}</span>
                          <span className="text-[9px] font-bold text-rose-400">CVSS {vuln.cvssScore}</span>
                        </div>
                        <p className="text-[10px] text-slate-300 truncate mt-0.5">{vuln.description}</p>
                      </div>
                    ))}
                    {totalCriticalAlerts === 0 && (
                      <div className="py-4 text-center text-slate-500 text-[11px]">
                        No critical alerts active.
                      </div>
                    )}
                  </div>
                  <div className="pt-2 border-t border-slate-800 text-center">
                    <button
                      onClick={() => {
                        setActiveTab('live');
                        setIsAlertsOpen(false);
                      }}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 font-medium"
                    >
                      View Live Monitoring &rarr;
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* User Profile Menu with Enterprise RBAC */}
            <div className="relative">
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className="flex items-center gap-2 pl-2 pr-2.5 py-1 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs transition-colors"
              >
                <div className={`w-6 h-6 rounded-full border flex items-center justify-center font-bold text-[10px] ${
                  currentUser.role === 'ADMIN'
                    ? 'bg-rose-950/80 border-rose-700 text-rose-300'
                    : currentUser.role === 'SECURITY_ANALYST'
                    ? 'bg-cyan-950/80 border-cyan-700 text-cyan-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400'
                }`}>
                  {currentUser.username ? currentUser.username.substring(0, 2).toUpperCase() : 'OP'}
                </div>
                <div className="text-left hidden sm:block">
                  <div className="text-[11px] font-semibold text-slate-200 leading-tight truncate max-w-[100px]">
                    {currentUser.username || 'operator'}
                  </div>
                  <div className={`text-[9px] font-mono leading-tight ${
                    currentUser.role === 'ADMIN' ? 'text-rose-400' : currentUser.role === 'SECURITY_ANALYST' ? 'text-cyan-400' : 'text-slate-400'
                  }`}>
                    {currentUser.role}
                  </div>
                </div>
                <ChevronDown className="w-3 h-3 text-slate-400" />
              </button>

              {/* Profile Dropdown */}
              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-3 z-50 text-xs font-sans">
                  <div className="pb-2 border-b border-slate-800">
                    <div className="font-semibold text-white truncate">{currentUser.email}</div>
                    <div className="flex items-center gap-1.5 mt-1">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${
                        currentUser.role === 'ADMIN'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : currentUser.role === 'SECURITY_ANALYST'
                          ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}>
                        {currentUser.role}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono truncate">
                        Tenant: {currentUser.tenant_id}
                      </span>
                    </div>
                  </div>
                  <div className="py-2 space-y-1 text-slate-300 text-[11px]">
                    <div className="flex items-center justify-between py-0.5">
                      <span>Permissions:</span>
                      <span className="text-emerald-400 font-mono font-semibold">
                        {currentUser.role === 'VIEWER' ? 'READ-ONLY' : 'READ / INVESTIGATE'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between py-0.5">
                      <span>Swarm Authorization:</span>
                      <span className={`font-mono font-semibold ${currentUser.role === 'VIEWER' ? 'text-rose-400' : 'text-cyan-400'}`}>
                        {currentUser.role === 'VIEWER' ? 'DENIED' : 'SUPERVISED'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between py-0.5">
                      <span>Security Mode:</span>
                      <span className="text-slate-400 font-mono">Enterprise RBAC</span>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-800 space-y-1.5">
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        setIsAuthModalOpen(true);
                      }}
                      className="w-full py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800 text-xs font-semibold transition-colors text-center"
                    >
                      Switch Role / Authenticate
                    </button>
                    <button
                      onClick={() => setIsUserMenuOpen(false)}
                      className="w-full text-center text-[10px] text-slate-400 hover:text-white pt-1"
                    >
                      Close Menu
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        currentUser={currentUser}
        onUserChanged={handleUserChanged}
      />
    </header>
  );
};
