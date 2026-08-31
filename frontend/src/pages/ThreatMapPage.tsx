import React, { useEffect, useState } from 'react';
import { Globe, ShieldAlert, Activity, RefreshCw, Zap, Flame, MapPin, Network, Share2 } from 'lucide-react';
import { threatFeedService } from '../services/api';

export const ThreatMapPage: React.FC = () => {
  const [mapData, setMapData] = useState<any | null>(null);
  const [graphData, setGraphData] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadMapAndGraphData();
  }, []);

  const loadMapAndGraphData = async () => {
    setIsLoading(true);
    try {
      const [mRes, gRes] = await Promise.all([
        threatFeedService.getThreatMap(),
        threatFeedService.getThreatGraph()
      ]);
      setMapData(mRes);
      setGraphData(gRes);
    } catch (err) {
      console.error('Failed to load threat map or graph data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="border-b border-cyber-border pb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
            <Globe className="w-6 h-6 text-rose-400" />
            <span>Global Cyber Threat Map & Relationship Graph</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time threat origin tracking, brand impersonation heatmaps, and connected threat node graphs.
          </p>
        </div>

        <button
          onClick={loadMapAndGraphData}
          disabled={isLoading}
          className="px-4 py-2.5 rounded-xl bg-cyber-card border border-cyber-border hover:border-rose-500 text-rose-400 font-mono text-xs font-bold flex items-center space-x-1.5 transition-all cursor-pointer disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Intelligence</span>
        </button>
      </div>

      {/* Overview Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
        <div className="p-5 bg-cyber-card border border-cyber-border rounded-xl space-y-1">
          <span className="text-slate-400 text-[10px] uppercase">TOTAL THREATS DETECTED</span>
          <p className="text-3xl font-bold text-rose-400">{mapData?.total_threats_detected ?? 84}</p>
          <span className="text-[10px] text-slate-500">Active High-Risk URL Probes</span>
        </div>

        <div className="p-5 bg-cyber-card border border-cyber-border rounded-xl space-y-1">
          <span className="text-slate-400 text-[10px] uppercase">TOP ATTACK VECTOR</span>
          <p className="text-2xl font-bold text-amber-400">Typosquatting & Homoglyphs</p>
          <span className="text-[10px] text-slate-500">42% of Global Campaigns</span>
        </div>

        <div className="p-5 bg-cyber-card border border-cyber-border rounded-xl space-y-1">
          <span className="text-slate-400 text-[10px] uppercase">MOST TARGETED BRAND</span>
          <p className="text-2xl font-bold text-cyan-400">PayPal / Microsoft 365</p>
          <span className="text-[10px] text-slate-500">Corporate Credentials & SSO</span>
        </div>
      </div>

      {/* Global Threat Map Graphic Container */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4 shadow-2xl relative overflow-hidden">
        <div className="flex items-center justify-between font-mono text-xs">
          <div className="flex items-center space-x-2 text-rose-400 font-bold">
            <Activity className="w-4 h-4 animate-pulse" />
            <span>LIVE THREAT ORIGINS & CAMPAIGN CLUSTERS</span>
          </div>
          <span className="text-[10px] text-slate-400">GEO-IP RANGE AUDIT</span>
        </div>

        {/* Visual Map Canvas Grid */}
        <div className="h-64 sm:h-80 bg-cyber-bg border border-cyber-border rounded-xl relative flex items-center justify-center overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(#334155_1px,transparent_1px)] [background-size:16px_16px] opacity-40" />

          {mapData?.threat_origins?.map((origin: any, idx: number) => (
            <div
              key={idx}
              className="absolute flex items-center space-x-2 group cursor-pointer"
              style={{
                top: `${(idx * 18 + 20) % 70 + 10}%`,
                left: `${(idx * 22 + 15) % 80 + 10}%`
              }}
            >
              <span className="relative flex h-3.5 w-3.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-rose-500 border border-slate-900"></span>
              </span>
              <div className="hidden group-hover:block bg-slate-900/90 border border-cyber-border p-2 rounded-lg text-[10px] font-mono text-slate-100 z-10 shadow-lg">
                <p className="font-bold text-rose-400">{origin.country} ({origin.region})</p>
                <p>Campaigns: {origin.active_campaigns} active</p>
                <p>Risk Rating: {origin.threat_level}</p>
              </div>
            </div>
          ))}

          <div className="relative text-center space-y-2 pointer-events-none">
            <Globe className="w-16 h-16 text-slate-700 mx-auto animate-spin-slow" />
            <p className="text-xs font-mono text-slate-400">
              Interactive Geo-Targeting Radar Monitoring Active Perimeter Signals
            </p>
          </div>
        </div>
      </div>

      {/* Threat Relationship Graph Visualizer */}
      {graphData && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4 shadow-2xl">
          <div className="flex items-center justify-between font-mono text-xs border-b border-cyber-border pb-3">
            <div className="flex items-center space-x-2 text-cyan-400 font-bold">
              <Network className="w-4 h-4" />
              <span>THREAT RELATIONSHIP GRAPH & INFRASTRUCTURE LINKAGES</span>
            </div>
            <span className="text-[10px] text-slate-400">{graphData.nodes_count} Nodes / {graphData.edges_count} Edges</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
            {graphData.nodes?.map((node: any, nIdx: number) => (
              <div key={nIdx} className="p-3.5 bg-cyber-bg border border-cyber-border rounded-xl space-y-1">
                <div className="flex items-center justify-between text-[10px]">
                  <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold">
                    {node.type}
                  </span>
                  <span className="text-rose-400 font-bold">Risk: {node.risk_score}</span>
                </div>
                <p className="font-bold text-slate-100 truncate">{node.label}</p>
                <p className="text-[10px] text-slate-400">{node.group}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
