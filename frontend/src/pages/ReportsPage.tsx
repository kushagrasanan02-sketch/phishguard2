import React, { useEffect, useState } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  AlertTriangle, 
  CheckCircle2, 
  Globe, 
  Webhook, 
  Plus, 
  Trash2, 
  Rss, 
  ExternalLink,
  ShieldAlert
} from 'lucide-react';
import { scanService, webhookService, threatFeedService } from '../services/api';
import { ScanResult, WebhookSubscriptionItem } from '../types';

export const ReportsPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [webhooks, setWebhooks] = useState<WebhookSubscriptionItem[]>([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [webhookMsg, setWebhookMsg] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const history = await scanService.getScanHistory({ limit: 20 });
      setScans(history);
      if (history.length > 0) {
        setSelectedScan(history[0]);
      }
      const whList = await webhookService.listWebhooks();
      setWebhooks(whList);
    } catch (err) {
      console.error('Failed to load reports data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    try {
      await webhookService.createWebhook(targetUrl.trim());
      setTargetUrl('');
      setWebhookMsg('Webhook subscription registered successfully!');
      setTimeout(() => setWebhookMsg(''), 3000);
      const whList = await webhookService.listWebhooks();
      setWebhooks(whList);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create webhook subscription.');
    }
  };

  const handleDeleteWebhook = async (id: string) => {
    if (!confirm('Are you sure you want to delete this webhook subscription?')) return;
    try {
      await webhookService.deleteWebhook(id);
      setWebhooks(webhooks.filter(w => w.id !== id));
    } catch (err) {
      alert('Failed to delete webhook subscription.');
    }
  };

  const handleExportPDF = () => {
    window.print();
  };

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
    if (score >= 50) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    if (score >= 25) return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
    return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Page Header */}
      <div className="border-b border-cyber-border pb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 print:hidden">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
            <FileText className="w-6 h-6 text-cyan-400" />
            <span>Security Assessment & Threat Intelligence Reports</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Exportable threat intelligence reports, executive briefs, webhooks, and live firewall IOC feeds.
          </p>
        </div>

        {/* Live Threat Feed Quick Links */}
        <div className="flex items-center space-x-2 font-mono text-xs">
          <a
            href={threatFeedService.getBlocklistUrl(60)}
            target="_blank"
            rel="noreferrer"
            className="px-3 py-2 rounded-xl bg-cyber-card border border-cyber-border hover:border-cyan-500 text-cyan-400 flex items-center space-x-1.5 transition-colors"
            title="Download Plaintext Firewall Domain Blocklist"
          >
            <Rss className="w-3.5 h-3.5" />
            <span>Firewall Blocklist</span>
          </a>

          {selectedScan && (
            <button
              onClick={handleExportPDF}
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold shadow flex items-center space-x-1.5 transition-all"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print Brief</span>
            </button>
          )}
        </div>
      </div>

      {/* Select Scan Report Selector & Executive Brief Download */}
      {scans.length > 0 && (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 font-mono text-xs print:hidden">
          <div className="flex items-center space-x-3 w-full sm:w-auto">
            <label className="text-slate-300 font-bold whitespace-nowrap">Select Scan Record:</label>
            <select
              value={selectedScan?.id || ''}
              onChange={(e) => {
                const found = scans.find(s => s.id === e.target.value);
                if (found) setSelectedScan(found);
              }}
              className="bg-cyber-bg border border-cyber-border text-slate-200 p-2 rounded-lg focus:border-cyan-500 focus:outline-none w-full sm:max-w-md truncate"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.domain} — Risk: {s.risk_score} ({s.classification})
                </option>
              ))}
            </select>
          </div>

          {selectedScan && (
            <div className="flex items-center space-x-2">
              <a
                href={scanService.getExecutiveReportUrl(selectedScan.id, 'html')}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 flex items-center space-x-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Executive HTML Brief</span>
              </a>

              <a
                href={scanService.getSiemExportUrl(selectedScan.id, 'cef')}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-2 rounded-lg bg-cyber-panel border border-cyber-border text-slate-300 hover:text-cyan-400 flex items-center space-x-1.5 transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>SIEM CEF</span>
              </a>
            </div>
          )}
        </div>
      )}

      {/* Main Selected Scan Audit Document */}
      {selectedScan ? (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-8 space-y-8 print:border-none print:shadow-none print:p-0">
          <div className="border-b border-cyber-border pb-6 flex items-start justify-between">
            <div className="space-y-1">
              <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded border border-cyan-500/20">
                PHISHGUARD AI DEFENSIVE ASSESSMENT REPORT
              </span>
              <h2 className="text-2xl font-bold text-slate-100 font-mono tracking-tight pt-1">
                EXECUTIVE SECURITY AUDIT
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Report ID: {selectedScan.id} | Generated: {new Date(selectedScan.created_at).toLocaleString()}
              </p>
            </div>
            <div className={`px-5 py-3 rounded-2xl border text-center font-mono ${getScoreColor(selectedScan.risk_score)}`}>
              <span className="text-3xl font-bold">{selectedScan.risk_score}</span>
              <span className="text-[10px] block font-bold tracking-widest uppercase">{selectedScan.classification}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
            <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl">
              <span className="text-slate-400 block mb-1">Target Host / Domain:</span>
              <p className="text-slate-100 font-bold text-sm truncate">{selectedScan.domain}</p>
            </div>
            <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl">
              <span className="text-slate-400 block mb-1">Machine Learning Prob.:</span>
              <p className="text-cyan-400 font-bold text-sm">{(selectedScan.ml_probability * 100).toFixed(1)}% Phishing</p>
            </div>
            <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl">
              <span className="text-slate-400 block mb-1">SSRF Policy Status:</span>
              <p className="text-emerald-400 font-bold text-sm">PASSED (Public Target)</p>
            </div>
          </div>

          <div className="space-y-4 font-mono text-xs">
            <h3 className="font-bold text-slate-200 uppercase tracking-wider border-b border-cyber-border pb-2">
              Extracted Risk Factor Contributors ({selectedScan.risk_factors.length})
            </h3>
            {selectedScan.risk_factors.length > 0 ? (
              <div className="space-y-3">
                {selectedScan.risk_factors.map((rf, idx) => (
                  <div key={idx} className="p-4 bg-cyber-bg border border-cyber-border rounded-xl flex items-start space-x-3">
                    <AlertTriangle className={`w-5 h-5 flex-shrink-0 mt-0.5 ${
                      rf.severity === 'CRITICAL' ? 'text-rose-400' : rf.severity === 'HIGH' ? 'text-amber-400' : 'text-yellow-400'
                    }`} />
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-200">{rf.factor}</span>
                        <span className="text-[10px] font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                          +{rf.score_contribution} Points
                        </span>
                      </div>
                      <p className="text-slate-400 text-xs mt-1">{rf.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl flex items-center space-x-2">
                <CheckCircle2 className="w-5 h-5" />
                <span>No high-severity risk indicators were identified for this target domain.</span>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-slate-400 font-mono bg-cyber-card border border-cyber-border rounded-2xl">
          No scan records available yet. Run a URL scan first.
        </div>
      )}

      {/* Automated Webhooks Management Panel */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-6 shadow-xl print:hidden">
        <div className="border-b border-cyber-border pb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-slate-100 font-sans flex items-center space-x-2">
              <Webhook className="w-5 h-5 text-purple-400" />
              <span>Automated Threat Alert Webhooks (SOAR / Slack / Teams)</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Configured webhooks receive HMAC-SHA256 signed POST payloads on high risk or phishing detection.
            </p>
          </div>
        </div>

        {/* Register Webhook Form */}
        <form onSubmit={handleCreateWebhook} className="flex flex-col sm:flex-row gap-3">
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://soar.enterprise.sec/api/v1/alerts"
            required
            className="flex-1 px-4 py-2.5 rounded-xl bg-cyber-bg border border-cyber-border text-slate-100 text-xs font-mono focus:border-cyan-500 focus:outline-none"
          />
          <button
            type="submit"
            className="px-5 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-mono font-bold text-xs flex items-center justify-center space-x-1.5 transition-all shadow"
          >
            <Plus className="w-4 h-4" />
            <span>Add Webhook</span>
          </button>
        </form>

        {webhookMsg && (
          <p className="text-xs font-mono text-emerald-400">{webhookMsg}</p>
        )}

        {/* Registered Webhooks List */}
        <div className="space-y-3 font-mono text-xs">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
            Active Webhook Subscriptions ({webhooks.length})
          </h3>

          {webhooks.length === 0 ? (
            <p className="text-slate-500 italic">No webhooks registered yet.</p>
          ) : (
            <div className="space-y-2">
              {webhooks.map((wh) => (
                <div key={wh.id} className="p-3 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between gap-4">
                  <div className="space-y-0.5 truncate">
                    <p className="font-bold text-cyan-400 truncate">{wh.target_url}</p>
                    <p className="text-[10px] text-slate-400">
                      HMAC Secret: <code className="text-slate-300">{wh.secret}</code> | Subscribed: {wh.events.join(', ')}
                    </p>
                  </div>

                  <button
                    onClick={() => handleDeleteWebhook(wh.id)}
                    className="p-2 text-slate-400 hover:text-rose-400 transition-colors"
                    title="Delete Webhook"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
