import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Globe, 
  AlertTriangle, 
  Activity, 
  TrendingUp, 
  ArrowUpRight,
  ExternalLink,
  Loader2,
  Radio,
  Bell
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import { scanService } from '../services/api';
import { DashboardStats, ScanResult } from '../types';

interface LiveAlertEvent {
  event: string;
  scan_id?: string;
  target?: string;
  url?: string;
  risk_score?: number;
  classification?: string;
  timestamp?: string;
}

export const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [liveAlerts, setLiveAlerts] = useState<LiveAlertEvent[]>([]);
  const [isWsConnected, setIsWsConnected] = useState<boolean>(false);

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        const [statsData, scansData] = await Promise.all([
          scanService.getDashboardStats(),
          scanService.getScanHistory({ limit: 10 })
        ]);
        setStats(statsData);
        setRecentScans(scansData);
      } catch (err) {
        console.error('Failed to fetch dashboard metrics:', err);
      } finally {
        setLoading(false);
      }
    };

    loadDashboardData();

    // Setup WebSockets Connection to Real-Time Telemetry Stream
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.hostname}:8000/api/v1/ws/alerts`;
    
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => {
        setIsWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data: LiveAlertEvent = JSON.parse(event.data);
          if (data.event === 'NEW_THREAT_SCAN') {
            setLiveAlerts((prev) => [data, ...prev.slice(0, 4)]);
            // Refresh aggregate stats
            scanService.getDashboardStats().then(setStats).catch(() => {});
          }
        } catch (e) {}
      };

      ws.onclose = () => setIsWsConnected(false);
      ws.onerror = () => setIsWsConnected(false);
    } catch (e) {}

    return () => {
      if (ws) ws.close();
    };
  }, []);

  const pieData = [
    { name: 'SAFE', value: stats?.threat_distribution?.SAFE || 0, color: '#10b981' },
    { name: 'GUARDED', value: stats?.threat_distribution?.GUARDED || 0, color: '#3b82f6' },
    { name: 'SUSPICIOUS', value: stats?.threat_distribution?.SUSPICIOUS || 0, color: '#f59e0b' },
    { name: 'PHISHING', value: stats?.threat_distribution?.PHISHING || 0, color: '#ef4444' },
  ];

  const getRiskBadge = (score: number) => {
    if (score >= 80) return { bg: 'bg-rose-500/10 text-rose-400 border-rose-500/30', label: 'CRITICAL' };
    if (score >= 60) return { bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30', label: 'HIGH' };
    if (score >= 40) return { bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30', label: 'MEDIUM' };
    if (score >= 20) return { bg: 'bg-blue-500/10 text-blue-400 border-blue-500/30', label: 'GUARDED' };
    return { bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', label: 'SAFE' };
  };

  if (loading) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <div className="flex flex-col items-center space-y-3">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
          <span className="text-xs font-mono text-slate-400">Loading Telemetry & SOC Dashboard Metrics...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-5">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
            <Activity className="w-6 h-6 text-cyan-400" />
            <span>SOC Security Dashboard</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time Threat Monitoring, URL Risk Analytics, & Machine Learning Telemetry
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {/* WebSocket Status Indicator */}
          <div className="px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border text-xs font-mono flex items-center space-x-2">
            <Radio className={`w-3.5 h-3.5 ${isWsConnected ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            <span className={isWsConnected ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
              {isWsConnected ? 'WS LIVE TELEMETRY' : 'OFFLINE'}
            </span>
          </div>

          <Link
            to="/scanner"
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 flex items-center space-x-2 transition-all"
          >
            <Globe className="w-4 h-4" />
            <span>Run New URL Scan</span>
          </Link>
        </div>
      </div>

      {/* Live Threat Telemetry Activity Stream (WebSockets) */}
      {liveAlerts.length > 0 && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-2xl p-4 space-y-3 font-mono text-xs animate-fadeIn">
          <div className="flex items-center justify-between">
            <span className="font-bold text-rose-300 flex items-center space-x-2">
              <Bell className="w-4 h-4 text-rose-400 animate-bounce" />
              <span>REAL-TIME THREAT ACTIVITY FEED (WEBSOCKETS BROADCAST)</span>
            </span>
            <span className="text-[10px] text-rose-400">{liveAlerts.length} Events Received</span>
          </div>
          <div className="space-y-2">
            {liveAlerts.map((alert, idx) => (
              <div key={idx} className="p-2.5 bg-cyber-bg/80 border border-rose-500/20 rounded-xl flex items-center justify-between text-slate-200">
                <div className="truncate max-w-lg">
                  <span className="font-bold text-rose-400 mr-2">[{alert.classification}]</span>
                  <span className="truncate">{alert.url}</span>
                </div>
                <span className="text-rose-400 font-bold">Risk: {alert.risk_score}/100</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5 Core Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Total Scans */}
        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono font-medium">TOTAL SCANS</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-3xl font-extrabold text-slate-100 font-mono">{stats?.total_scans || 0}</p>
          <p className="text-[11px] text-emerald-400 font-mono flex items-center">
            <TrendingUp className="w-3 h-3 mr-1" /> Active database persistence
          </p>
        </div>

        {/* Phishing Detected */}
        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono font-medium">PHISHING DETECTED</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <p className="text-3xl font-extrabold text-rose-400 font-mono">{stats?.phishing_detected || 0}</p>
          <p className="text-[11px] text-rose-400 font-mono font-medium">High severity threats</p>
        </div>

        {/* Safe URLs */}
        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono font-medium">SAFE URLS</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-3xl font-extrabold text-emerald-400 font-mono">{stats?.safe_urls || 0}</p>
          <p className="text-[11px] text-slate-400 font-mono">Clean telemetry targets</p>
        </div>

        {/* High Risk URLs */}
        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono font-medium">HIGH RISK URLS</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-3xl font-extrabold text-amber-400 font-mono">{stats?.high_risk_urls || 0}</p>
          <p className="text-[11px] text-amber-400 font-mono">Score &gt;= 60</p>
        </div>

        {/* Average Risk Score */}
        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono font-medium">AVG RISK SCORE</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <p className="text-3xl font-extrabold text-slate-100 font-mono">{stats?.average_risk_score || 0}/100</p>
          <p className="text-[11px] text-blue-400 font-mono">Mean risk index</p>
        </div>
      </div>

      {/* Visual Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution Chart */}
        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 font-mono">THREAT CLASSIFICATION</h3>
            <span className="text-[10px] font-mono text-slate-400">LIVE AGGREGATE</span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#1f293d', borderRadius: '8px' }}
                  itemStyle={{ color: '#f3f4f6', fontSize: '12px', fontFamily: 'monospace' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2 border-t border-cyber-border">
            {pieData.map((item) => (
              <div key={item.name} className="flex items-center space-x-2">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-400">{item.name}:</span>
                <span className="text-slate-200 font-semibold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Telemetry Architecture Card */}
        <div className="lg:col-span-2 bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-200 font-mono">DEFENSIVE PROBE & TELEMETRY ENGINE</h3>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              PhishGuard AI executes defensive probes with strict SSRF controls. Private IPv4/IPv6 subnets, loopback interfaces, and cloud metadata endpoints are automatically filtered.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-3 text-xs font-mono border-t border-cyber-border pt-4">
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
              <span className="text-[10px] text-slate-400">SSRF RULESET</span>
              <p className="text-cyan-400 font-bold">RFC 1918 Enforced</p>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
              <span className="text-[10px] text-slate-400">RISK ENGINE</span>
              <p className="text-emerald-400 font-bold">Transparent Weights</p>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
              <span className="text-[10px] text-slate-400">ML CLASSIFIER</span>
              <p className="text-purple-400 font-bold">Random Forest</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 font-mono">RECENT SECURITY PROBES</h3>
          <Link to="/history" className="text-xs font-mono text-cyan-400 hover:underline flex items-center space-x-1">
            <span>View Full History</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          {recentScans.length === 0 ? (
            <div className="text-center py-8 text-xs font-mono text-slate-400">
              No recent security probes found in database. Run a URL scan to populate real-time logs.
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Target URL</th>
                  <th className="py-3 px-4">Domain</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Probe Date</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-xs font-mono">
                {recentScans.map((scan) => {
                  const badge = getRiskBadge(scan.risk_score);
                  return (
                    <tr key={scan.id} className="hover:bg-cyber-panel/40 transition-colors">
                      <td className="py-3 px-4 text-slate-200 font-mono truncate max-w-xs" title={scan.url}>
                        {scan.url}
                      </td>
                      <td className="py-3 px-4 text-slate-400">{scan.domain}</td>
                      <td className="py-3 px-4">
                        <span className="font-extrabold text-slate-100">{scan.risk_score}</span>
                        <span className="text-slate-500 text-[10px]">/100</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${badge.bg}`}>
                          {scan.classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link to="/scanner" className="text-cyan-400 hover:text-cyan-300 font-semibold text-[11px] inline-flex items-center space-x-1">
                          <span>Scan Again</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
