import React, { useState } from 'react';
import {
  Shield,
  Lock,
  User,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  LogOut,
  X,
  Radio,
  ArrowRight,
} from 'lucide-react';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser: {
    email: string;
    username: string;
    role: string;
    tenant_id: string;
  };
  onUserChanged: (newUser: any) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  currentUser,
  onUserChanged,
}) => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleLogin = async (customId?: string, customPass?: string) => {
    setIsLoading(true);
    setError(null);
    setSuccessMsg(null);

    const loginId = customId || identifier;
    const loginPass = customPass || password;

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: loginId, password: loginPass }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        setError(data.error || 'Authentication failed');
      } else {
        localStorage.setItem('crisp_token', data.token);
        localStorage.setItem('crisp_user', JSON.stringify(data.user));
        setSuccessMsg(`Authenticated as ${data.user.email} [${data.user.role}]`);
        onUserChanged(data.user);
        setTimeout(() => {
          onClose();
        }, 800);
      }
    } catch (err: any) {
      setError(err.message || 'Login network error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = async () => {
    setIsLoading(true);
    try {
      const token = localStorage.getItem('crisp_token');
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      localStorage.removeItem('crisp_token');
      localStorage.removeItem('crisp_user');
      // Default to viewer session
      onUserChanged({
        email: 'viewer@crisp.local',
        username: 'viewer',
        role: 'VIEWER',
        tenant_id: 'default_tenant',
      });
      setSuccessMsg('Logged out successfully.');
      setTimeout(() => onClose(), 800);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const PRESET_ACCOUNTS = [
    {
      role: 'ADMIN',
      email: 'admin@crisp.local',
      pass: 'Admin#Crisp2026!',
      label: 'Full Platform Admin',
      desc: 'All write operations, user management, audit logs, provider config',
      badgeColor: 'bg-rose-950 text-rose-300 border-rose-800',
    },
    {
      role: 'SECURITY_ANALYST',
      email: 'saifkar98k@gmail.com',
      pass: 'Crisp#Analyst2026!',
      label: 'Primary SOC Analyst',
      desc: 'Supervised swarm investigations, remediation queue, findings triage',
      badgeColor: 'bg-cyan-950 text-cyan-300 border-cyan-800',
    },
    {
      role: 'VIEWER',
      email: 'viewer@crisp.local',
      pass: 'Viewer#Crisp2026!',
      label: 'Read-Only Viewer',
      desc: 'Read-only dashboards and metrics; mutation & agent access blocked',
      badgeColor: 'bg-slate-800 text-slate-300 border-slate-700',
    },
  ];

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-5">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-300 font-bold">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-white text-sm">Enterprise Authentication &amp; RBAC</h3>
              <p className="text-[11px] text-slate-400 font-mono">CRISP Security Governance</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Current Active Session Status */}
        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
          <div className="text-xs">
            <span className="text-slate-500 font-mono block text-[10px]">CURRENT OPERATOR</span>
            <span className="font-mono font-semibold text-slate-200">{currentUser.email}</span>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                {currentUser.role}
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                Tenant: {currentUser.tenant_id}
              </span>
            </div>
          </div>
          <button
            onClick={handleLogout}
            disabled={isLoading}
            className="px-2.5 py-1 rounded-lg bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs font-semibold flex items-center gap-1 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Logout</span>
          </button>
        </div>

        {/* Feedback message */}
        {error && (
          <div className="p-2.5 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {successMsg && (
          <div className="p-2.5 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Quick Enterprise Role Switcher */}
        <div className="space-y-2">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Quick Enterprise Role Switch
          </div>
          <div className="space-y-1.5">
            {PRESET_ACCOUNTS.map((acc) => {
              const isCurrent = currentUser.email === acc.email;
              return (
                <button
                  key={acc.role}
                  onClick={() => handleLogin(acc.email, acc.pass)}
                  disabled={isLoading || isCurrent}
                  className={`w-full p-2.5 rounded-xl border text-left transition-all flex items-center justify-between ${
                    isCurrent
                      ? 'bg-slate-800/80 border-cyan-500/80 text-white'
                      : 'bg-slate-950/60 hover:bg-slate-800 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="text-xs">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold border ${acc.badgeColor}`}>
                        {acc.role}
                      </span>
                      <span className="font-semibold text-slate-200">{acc.label}</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-0.5">{acc.desc}</p>
                  </div>
                  {isCurrent ? (
                    <span className="text-[10px] font-mono font-bold text-cyan-400">ACTIVE</span>
                  ) : (
                    <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Custom Login Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleLogin();
          }}
          className="space-y-3 pt-3 border-t border-slate-800"
        >
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Or Login with Custom Credentials
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Email or Username</label>
            <div className="relative">
              <User className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="user@crisp.local"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Password</label>
            <div className="relative">
              <KeyRound className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading || !identifier || !password}
            className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors"
          >
            {isLoading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
};
