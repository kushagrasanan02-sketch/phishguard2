import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Globe, Mail, History, FileText, ShieldCheck, Home, Key } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Sidebar: React.FC = () => {
  const { user } = useAuth();

  const navItems = [
    { label: 'Landing Page', path: '/', icon: Home, public: true },
    { label: 'SOC Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { label: 'URL Scanner', path: '/scanner', icon: Globe },
    { label: 'Email Security', path: '/email', icon: Mail },
    { label: 'Global Threat Map', path: '/threat-map', icon: Globe },
    { label: 'Scan History', path: '/history', icon: History },
    { label: 'Security Reports', path: '/reports', icon: FileText },
    { label: 'API Keys & Profile', path: '/profile', icon: Key },
  ];

  if (user?.role === 'ADMIN') {
    navItems.push({ label: 'Admin Console', path: '/admin', icon: ShieldCheck });
  }

  return (
    <aside className="w-64 border-r border-cyber-border bg-cyber-card/60 min-h-[calc(100vh-4rem)] p-4 flex flex-col justify-between">
      <div className="space-y-6">
        <div>
          <p className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500 px-3 mb-2">
            Navigation Menu
          </p>
          <nav className="space-y-1">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold shadow-inner'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-panel/60'
                  }`
                }
              >
                <item.icon className="w-4 h-4" />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </nav>
        </div>

        {/* Security Disclaimer Box */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-cyber-border/80 text-[11px] space-y-1.5">
          <div className="flex items-center space-x-1.5 text-cyan-400 font-mono font-medium">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Defensive Mode</span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            All analysis operations are non-interactive. HTTP requests execute with strict SSRF controls and zero script execution.
          </p>
        </div>
      </div>

      {/* System Footer Info */}
      <div className="pt-4 border-t border-cyber-border/60 px-2 text-[10px] text-slate-500 font-mono flex items-center justify-between">
        <span>PHISHGUARD SEC</span>
        <span className="text-emerald-400 font-semibold">PROTECTED</span>
      </div>
    </aside>
  );
};
