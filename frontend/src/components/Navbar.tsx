import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Activity, LogOut, User as UserIcon, ShieldAlert, Cpu } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/api';

export const Navbar: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();
  const [dbHealthy, setDbHealthy] = useState<boolean>(true);

  useEffect(() => {
    authService.getHealth()
      .then(res => setDbHealthy(res.database === 'healthy'))
      .catch(() => setDbHealthy(false));
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="h-16 border-b border-cyber-border bg-cyber-card/80 backdrop-blur-md sticky top-0 z-40 px-6 flex items-center justify-between">
      {/* Brand Header */}
      <div className="flex items-center space-x-3">
        <Link to="/" className="flex items-center space-x-2.5 group">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 group-hover:bg-cyan-500/20 transition-all">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-wider text-slate-100 font-mono">PHISHGUARD</span>
              <span className="text-xs px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-mono font-semibold">AI v1.0</span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono tracking-wide hidden sm:block">PHISHING DETECTION & RISK ENGINE</p>
          </div>
        </Link>
      </div>

      {/* Right Side Status & User Menu */}
      <div className="flex items-center space-x-4">
        {/* System Health Badge */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-cyber-bg border border-cyber-border text-xs font-mono">
          <Activity className={`w-3.5 h-3.5 ${dbHealthy ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
          <span className="text-slate-400">ENGINE:</span>
          <span className={dbHealthy ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
            {dbHealthy ? 'ONLINE' : 'DEGRADED'}
          </span>
        </div>

        {isAuthenticated ? (
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-cyber-panel border border-cyber-border">
              <UserIcon className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono text-slate-200">{user?.email}</span>
              {user?.role === 'ADMIN' && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono font-bold">
                  ADMIN
                </span>
              )}
            </div>

            <button
              onClick={handleLogout}
              className="p-2 rounded-lg bg-cyber-panel border border-cyber-border text-slate-400 hover:text-rose-400 hover:border-rose-500/40 transition-colors"
              title="Logout Security Session"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="flex items-center space-x-2">
            <Link
              to="/login"
              className="px-4 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white transition-colors"
            >
              Sign In
            </Link>
            <Link
              to="/register"
              className="px-4 py-1.5 rounded-lg text-xs font-medium bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold shadow-lg shadow-cyan-500/20 transition-all"
            >
              Get Started
            </Link>
          </div>
        )}
      </div>
    </header>
  );
};
