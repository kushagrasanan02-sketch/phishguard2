import React, { useState } from 'react';
import { 
  Globe, 
  Search, 
  RefreshCw, 
  AlertTriangle, 
  ShieldCheck, 
  Cpu, 
  CheckCircle2, 
  AlertCircle,
  Layers,
  FileText,
  Zap,
  ExternalLink,
  Download,
  Info
} from 'lucide-react';
import { scanService } from '../services/api';
import { ScanResult, BatchScanResponse } from '../types';

export const URLScannerPage: React.FC = () => {
  const [mode, setMode] = useState<'single' | 'batch'>('single');
  const [url, setUrl] = useState('');
  const [batchUrls, setBatchUrls] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [batchResult, setBatchResult] = useState<BatchScanResponse | null>(null);

  const handleSingleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setError('');
    setLoading(true);
    setScanResult(null);

    try {
      const result = await scanService.scanUrl(url.trim());
      setScanResult(result);
    } catch (err: any) {
      setError(
        err.response?.data?.detail || 
        'Security analysis probe failed. Please verify target URL structure.'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleBatchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const urlList = batchUrls
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 0);

    if (urlList.length === 0) return;

    setError('');
    setLoading(true);
    setBatchResult(null);

    try {
      const result = await scanService.scanBatch(urlList);
      setBatchResult(result);
    } catch (err: any) {
      setError(
        err.response?.data?.detail || 
        'Batch probe execution failed. Maximum 50 URLs allowed per batch request.'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setUrl('');
    setBatchUrls('');
    setError('');
    setScanResult(null);
    setBatchResult(null);
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return { text: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/30', bar: 'bg-rose-500' };
    if (score >= 60) return { text: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', bar: 'bg-orange-500' };
    if (score >= 40) return { text: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30', bar: 'bg-amber-500' };
    if (score >= 20) return { text: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30', bar: 'bg-blue-500' };
    return { text: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', bar: 'bg-emerald-500' };
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Page Header & Mode Selector */}
      <div className="border-b border-cyber-border pb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
            <Globe className="w-6 h-6 text-cyan-400" />
            <span>AI URL Phishing & Security Scanner</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Non-interactive security probes, lexical feature extraction, and transparent 0–100 risk scoring.
          </p>
        </div>

        {/* Single vs Batch Toggle */}
        <div className="flex bg-cyber-card p-1 rounded-xl border border-cyber-border self-start sm:self-auto font-mono text-xs">
          <button
            type="button"
            onClick={() => { setMode('single'); handleClear(); }}
            className={`px-3.5 py-1.5 rounded-lg flex items-center space-x-2 transition-all ${
              mode === 'single' ? 'bg-cyan-500 text-slate-950 font-bold shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Search className="w-3.5 h-3.5" />
            <span>Single URL</span>
          </button>
          <button
            type="button"
            onClick={() => { setMode('batch'); handleClear(); }}
            className={`px-3.5 py-1.5 rounded-lg flex items-center space-x-2 transition-all ${
              mode === 'batch' ? 'bg-cyan-500 text-slate-950 font-bold shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Batch Probe</span>
          </button>
        </div>
      </div>

      {/* Mode 1: Single URL Scanner Form */}
      {mode === 'single' && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4 shadow-xl">
          <form onSubmit={handleSingleScan} className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                  Target URL Address
                </label>
                <span className="text-[11px] font-mono text-cyan-400">SSRF PROTECTED PROBE</span>
              </div>

              <div className="relative">
                <Globe className="w-5 h-5 text-slate-500 absolute left-3.5 top-3.5" />
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="e.g. https://paypa1-security-verification.com/login"
                  className="w-full pl-11 pr-4 py-3 rounded-xl bg-cyber-bg border border-cyber-border text-slate-100 text-sm font-mono focus:border-cyan-500 focus:outline-none transition-colors"
                />
              </div>

              {/* Quick Example Chips */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <span className="text-[10px] font-mono text-slate-500">Test Examples:</span>
                <button
                  type="button"
                  onClick={() => setUrl('https://account.microsoft.com/services')}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-panel text-slate-300 hover:text-cyan-400 border border-cyber-border transition-colors"
                >
                  Safe URL (Microsoft)
                </button>
                <button
                  type="button"
                  onClick={() => setUrl('http://paypa1-account-verify.xyz/login?ref=urgent')}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-panel text-slate-300 hover:text-rose-400 border border-cyber-border transition-colors"
                >
                  Phishing Indicator (Paypa1)
                </button>
                <button
                  type="button"
                  onClick={() => setUrl('http://127.0.0.1:8000/admin')}
                  className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-panel text-slate-300 hover:text-amber-400 border border-cyber-border transition-colors"
                >
                  SSRF Test (Private IP)
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-3 pt-2">
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 flex items-center space-x-2 transition-all disabled:opacity-50"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                <span>{loading ? 'Executing Probe Telemetry...' : 'Analyze URL'}</span>
              </button>

              <button
                type="button"
                onClick={handleClear}
                className="px-5 py-3 rounded-xl bg-cyber-panel border border-cyber-border text-slate-400 hover:text-slate-200 text-sm font-mono transition-colors"
              >
                Clear
              </button>
            </div>
          </form>

          {error && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono space-y-1 flex items-start space-x-3">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-bold">PROBE REJECTED BY SECURITY CONTROLS</p>
                <p className="text-slate-300">{error}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Mode 2: Batch URL Scanner Form */}
      {mode === 'batch' && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4 shadow-xl">
          <form onSubmit={handleBatchScan} className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                  Bulk Target URL List (One per line, Max 50)
                </label>
                <span className="text-[11px] font-mono text-cyan-400">BATCH THREAT PROBE</span>
              </div>

              <textarea
                rows={6}
                value={batchUrls}
                onChange={(e) => setBatchUrls(e.target.value)}
                placeholder="https://google.com&#10;https://paypal.com&#10;http://paypa1-security-login.xyz/auth"
                className="w-full p-4 rounded-xl bg-cyber-bg border border-cyber-border text-slate-100 text-xs font-mono focus:border-cyan-500 focus:outline-none transition-colors"
              />

              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                <span>Total Lines: {batchUrls.split('\n').filter(u => u.trim()).length} URLs</span>
                <button
                  type="button"
                  onClick={() => setBatchUrls("https://google.com\nhttps://paypal.com\nhttp://paypa1-account-login.xyz/verify")}
                  className="text-cyan-400 hover:underline"
                >
                  Load Sample Batch Payload
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-3 pt-2">
              <button
                type="submit"
                disabled={loading || !batchUrls.trim()}
                className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 flex items-center space-x-2 transition-all disabled:opacity-50"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Layers className="w-4 h-4" />}
                <span>{loading ? 'Executing Batch Analysis...' : 'Execute Batch Probe'}</span>
              </button>

              <button
                type="button"
                onClick={handleClear}
                className="px-5 py-3 rounded-xl bg-cyber-panel border border-cyber-border text-slate-400 hover:text-slate-200 text-sm font-mono transition-colors"
              >
                Clear
              </button>
            </div>
          </form>

          {error && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono space-y-1 flex items-start space-x-3">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-bold">BATCH REJECTED BY SECURITY CONTROLS</p>
                <p className="text-slate-300">{error}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Loading State Skeleton */}
      {loading && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-8 space-y-6 animate-pulse">
          <div className="h-6 bg-cyber-panel rounded w-1/3" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="h-40 bg-cyber-panel rounded-xl" />
            <div className="h-40 bg-cyber-panel rounded-xl" />
          </div>
        </div>
      )}

      {/* Single Scan Output */}
      {mode === 'single' && scanResult && !loading && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 sm:p-8 space-y-8 shadow-2xl">
          <div className="border-b border-cyber-border pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 px-2.5 py-0.5 rounded border border-cyan-500/30">
                  SECURITY REPORT #{scanResult.id.substring(0, 8)}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {new Date(scanResult.created_at).toLocaleString()}
                </span>
              </div>
              <h2 className="text-xl font-bold text-slate-100 font-mono truncate max-w-xl" title={scanResult.url}>
                {scanResult.url}
              </h2>
              <p className="text-xs text-slate-400 font-mono">Target Domain: <span className="text-cyan-400 font-semibold">{scanResult.domain}</span></p>
            </div>

            <div className="flex items-center space-x-3">
              <a
                href={scanService.getExecutiveReportUrl(scanResult.id, 'html')}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-2 rounded-lg bg-cyber-panel border border-cyber-border hover:border-cyan-500 text-xs font-mono text-cyan-400 flex items-center space-x-1.5 transition-all"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Executive Brief (HTML)</span>
              </a>

              <div className="text-right pl-2 border-l border-cyber-border">
                <div className="flex items-baseline space-x-1">
                  <span className={`text-3xl font-extrabold font-mono ${getRiskScoreColor(scanResult.risk_score).text}`}>
                    {scanResult.risk_score}
                  </span>
                  <span className="text-xs font-mono text-slate-500">/100</span>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${getRiskScoreColor(scanResult.risk_score).bg}`}>
                  {scanResult.classification}
                </span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-cyber-bg border border-cyber-border rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-xs font-mono font-bold text-slate-200">
                  <Cpu className="w-4 h-4 text-purple-400" />
                  <span>AI MODEL ASSESSMENT</span>
                </div>
                <span className="text-[10px] font-mono text-slate-400">RANDOM FOREST v1.0</span>
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-400">Phishing Probability:</span>
                  <span className="text-purple-400 font-bold">{(scanResult.ml_probability * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full bg-cyber-panel h-2.5 rounded-full overflow-hidden">
                  <div 
                    className="bg-gradient-to-r from-purple-500 to-cyan-400 h-full transition-all duration-500" 
                    style={{ width: `${scanResult.ml_probability * 100}%` }}
                  />
                </div>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                Interpretable machine learning feature assessment evaluating structural vectors and lexical entropy patterns.
              </p>
            </div>

            <div className="bg-cyber-bg border border-cyber-border rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-xs font-mono font-bold text-slate-200">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  <span>TRANSPARENT RISK SCORE ENGINE</span>
                </div>
                <span className="text-[10px] font-mono text-slate-400">0–100 SCALE</span>
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-400">Risk Severity Rating:</span>
                  <span className={`font-bold ${getRiskScoreColor(scanResult.risk_score).text}`}>
                    {scanResult.risk_score} / 100 ({scanResult.classification})
                  </span>
                </div>
                <div className="w-full bg-cyber-panel h-2.5 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-500 ${getRiskScoreColor(scanResult.risk_score).bar}`} 
                    style={{ width: `${scanResult.risk_score}%` }}
                  />
                </div>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                Weighted calculation aggregating IP targets, brand similarity, subdomains, punycode, and suspicious keywords.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Batch Scan Summary Output */}
      {mode === 'batch' && batchResult && !loading && (
        <div className="space-y-6">
          {/* Batch Aggregate Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-cyber-card border border-cyber-border rounded-xl font-mono space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">PROCESSED URLS</span>
              <p className="text-2xl font-bold text-slate-100">{batchResult.total_processed}</p>
            </div>
            <div className="p-4 bg-cyber-card border border-cyber-border rounded-xl font-mono space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">SAFE ASSETS</span>
              <p className="text-2xl font-bold text-emerald-400">{batchResult.safe_count}</p>
            </div>
            <div className="p-4 bg-cyber-card border border-cyber-border rounded-xl font-mono space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">THREATS / PHISHING</span>
              <p className="text-2xl font-bold text-rose-400">{batchResult.phishing_count}</p>
            </div>
            <div className="p-4 bg-cyber-card border border-cyber-border rounded-xl font-mono space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">AVG BATCH RISK</span>
              <p className="text-2xl font-bold text-amber-400">{batchResult.average_risk_score} / 100</p>
            </div>
          </div>

          {/* Batch Items List */}
          <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider flex items-center justify-between">
              <span>Batch Inspection Results ({batchResult.scans.length})</span>
              <span className="text-xs text-cyan-400 font-normal">All scans persisted to history</span>
            </h3>

            <div className="space-y-3">
              {batchResult.scans.map((scan) => (
                <div key={scan.id} className="p-4 bg-cyber-bg border border-cyber-border rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono">
                  <div className="space-y-1 truncate max-w-xl">
                    <p className="text-xs font-bold text-slate-100 truncate">{scan.url}</p>
                    <p className="text-[11px] text-slate-400">Domain: {scan.domain}</p>
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className="text-right">
                      <span className={`text-lg font-extrabold ${getRiskScoreColor(scan.risk_score).text}`}>
                        {scan.risk_score}
                      </span>
                      <span className="text-[10px] text-slate-500">/100</span>
                    </div>

                    <span className={`px-2.5 py-1 rounded text-xs font-bold ${getRiskScoreColor(scan.risk_score).bg}`}>
                      {scan.classification}
                    </span>

                    <a
                      href={scanService.getExecutiveReportUrl(scan.id, 'html')}
                      target="_blank"
                      rel="noreferrer"
                      className="p-2 rounded bg-cyber-panel border border-cyber-border text-cyan-400 hover:border-cyan-500 transition-colors"
                      title="Download Executive HTML Brief"
                    >
                      <Download className="w-4 h-4" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
