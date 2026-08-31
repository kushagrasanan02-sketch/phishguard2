import React, { useState } from 'react';
import { Mail, Upload, FileText, AlertCircle, ShieldAlert, CheckCircle2, Loader2, ExternalLink, ShieldX, AlertTriangle } from 'lucide-react';
import { emailService } from '../services/api';
import { EmailScanResult } from '../types';
import { useNavigate } from 'react-router-dom';

export const EmailAnalyzerPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('paste');
  const [rawEmail, setRawEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<EmailScanResult | null>(null);
  const navigate = useNavigate();

  const handleInspectText = async () => {
    if (!rawEmail.trim()) {
      setError('Please paste raw email headers or body content.');
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const result = await emailService.scanEmailText(rawEmail);
      setScanResult(result);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to inspect email headers.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    setError(null);
    try {
      const result = await emailService.scanEmailFile(file);
      setScanResult(result);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to analyze .eml file.');
    } finally {
      setIsLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
    if (score >= 50) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    if (score >= 25) return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
    return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      <div className="border-b border-cyber-border pb-5">
        <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
          <Mail className="w-6 h-6 text-cyan-400" />
          <span>Email Security & Header Inspector</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Analyze raw email headers, SPF/DKIM/DMARC authentication, reply-to mismatches, and embedded link risk.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-cyber-border space-x-4">
        <button
          onClick={() => setActiveTab('paste')}
          className={`pb-3 text-xs font-mono font-bold transition-all border-b-2 ${
            activeTab === 'paste'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Paste Raw Headers / Content
        </button>
        <button
          onClick={() => setActiveTab('upload')}
          className={`pb-3 text-xs font-mono font-bold transition-all border-b-2 ${
            activeTab === 'upload'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Upload .EML File
        </button>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Input Section */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4">
        {activeTab === 'paste' ? (
          <div className="space-y-4">
            <label className="text-xs font-mono font-bold text-slate-300">
              Raw Email RFC 822 Headers or Body
            </label>
            <textarea
              rows={8}
              value={rawEmail}
              onChange={(e) => setRawEmail(e.target.value)}
              placeholder="Paste email headers here (From:, Received:, Reply-To:, Authentication-Results:)..."
              className="w-full p-4 rounded-xl bg-cyber-bg border border-cyber-border text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none transition-colors"
            />
            <button
              onClick={handleInspectText}
              disabled={isLoading}
              className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 flex items-center space-x-2 transition-all cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Inspecting Telemetry...</span>
                </>
              ) : (
                <>
                  <Mail className="w-4 h-4" />
                  <span>Inspect Email Headers</span>
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="relative border-2 border-dashed border-cyber-border hover:border-cyan-500/40 rounded-xl p-12 text-center space-y-3 transition-colors">
            <input
              type="file"
              accept=".eml,.msg,.txt"
              onChange={handleFileUpload}
              className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
            />
            <Upload className="w-8 h-8 text-cyan-400 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">
              {isLoading ? 'Uploading & Inspecting...' : 'Click or Drag .eml file here'}
            </p>
            <p className="text-xs text-slate-500 font-mono">Supports standard .eml and RFC 822 email formats</p>
          </div>
        )}
      </div>

      {/* Analysis Results View */}
      {scanResult && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-cyber-border pb-4">
            <div>
              <span className="text-[10px] font-mono text-slate-400">EMAIL ASSESSMENT REPORT</span>
              <h2 className="text-lg font-bold text-slate-100 font-mono">{scanResult.subject || 'No Subject'}</h2>
              <p className="text-xs text-slate-400 font-mono mt-0.5">From: {scanResult.sender}</p>
            </div>
            <div className={`px-4 py-2 rounded-xl border text-center font-mono ${getScoreColor(scanResult.risk_score)}`}>
              <span className="text-2xl font-bold">{scanResult.risk_score}</span>
              <span className="text-[10px] block font-bold tracking-widest">{scanResult.classification}</span>
            </div>
          </div>

          {/* Authentication Checks Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl space-y-1">
              <span className="text-xs font-mono text-slate-400">SPF Validation</span>
              <div className="flex items-center space-x-2">
                {scanResult.spf_result === 'FAIL' ? (
                  <ShieldX className="w-4 h-4 text-rose-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                <span className={`text-sm font-mono font-bold ${scanResult.spf_result === 'FAIL' ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {scanResult.spf_result || 'PASS'}
                </span>
              </div>
            </div>

            <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl space-y-1">
              <span className="text-xs font-mono text-slate-400">DKIM Signature</span>
              <div className="flex items-center space-x-2">
                {scanResult.dkim_result === 'FAIL' ? (
                  <ShieldX className="w-4 h-4 text-rose-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                <span className={`text-sm font-mono font-bold ${scanResult.dkim_result === 'FAIL' ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {scanResult.dkim_result || 'PASS'}
                </span>
              </div>
            </div>

            <div className="p-4 bg-cyber-bg border border-cyber-border rounded-xl space-y-1">
              <span className="text-xs font-mono text-slate-400">DMARC Policy</span>
              <div className="flex items-center space-x-2">
                {scanResult.dmarc_result === 'FAIL' ? (
                  <ShieldX className="w-4 h-4 text-rose-400" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                )}
                <span className={`text-sm font-mono font-bold ${scanResult.dmarc_result === 'FAIL' ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {scanResult.dmarc_result || 'PASS'}
                </span>
              </div>
            </div>
          </div>

          {/* BEC Reply-To Mismatch Warning */}
          {scanResult.reply_to_mismatch && (
            <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start space-x-3 text-rose-300 font-mono text-xs">
              <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
              <div>
                <strong className="block text-rose-200">BEC Executive Spoofing Warning:</strong>
                <span>The Reply-To address domain differs from the From domain, indicating potential email spoofing or credential theft.</span>
              </div>
            </div>
          )}

          {/* Indicators List */}
          {scanResult.indicators && scanResult.indicators.length > 0 && (
            <div className="space-y-2 font-mono text-xs">
              <h3 className="font-bold text-slate-300 uppercase tracking-wider">Security Telemetry Indicators</h3>
              <ul className="space-y-1.5 text-slate-300">
                {scanResult.indicators.map((ind, i) => (
                  <li key={i} className="flex items-center space-x-2 text-rose-400 bg-rose-500/5 px-3 py-2 rounded border border-rose-500/10">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    <span>{ind}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Embedded URLs Analysis */}
          {scanResult.url_scans && scanResult.url_scans.length > 0 && (
            <div className="space-y-3 font-mono text-xs">
              <h3 className="font-bold text-slate-300 uppercase tracking-wider">Embedded Links Inspection</h3>
              <div className="divide-y divide-cyber-border border border-cyber-border rounded-xl overflow-hidden">
                {scanResult.url_scans.map((uscan, i) => (
                  <div key={i} className="p-3 bg-cyber-bg flex items-center justify-between">
                    <div className="truncate max-w-lg">
                      <span className="text-slate-200 font-semibold truncate block">{uscan.url}</span>
                      <span className="text-slate-500 text-[10px]">{uscan.domain}</span>
                    </div>
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${
                        uscan.risk_score >= 60 ? 'text-rose-400 border-rose-500/30 bg-rose-500/10' : 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
                      }`}>
                        Risk: {uscan.risk_score}
                      </span>
                      <button
                        onClick={() => navigate(`/scanner?url=${encodeURIComponent(uscan.url)}`)}
                        className="p-1.5 hover:bg-cyber-panel rounded text-cyan-400 transition-colors"
                        title="Scan full URL features"
                      >
                        <ExternalLink className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
