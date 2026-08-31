import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { History, Search, Download, ExternalLink, Loader2, Filter, X } from 'lucide-react';
import { scanService } from '../services/api';
import { ScanResult } from '../types';

export const ScanHistoryPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [minRisk, setMinRisk] = useState<number>(0);
  const [selectedScanModal, setSelectedScanModal] = useState<ScanResult | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await scanService.getScanHistory({
        limit: 100,
        q: searchTerm || undefined,
        classification: classificationFilter !== 'ALL' ? classificationFilter : undefined,
        min_risk: minRisk > 0 ? minRisk : undefined
      });
      setScans(data);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [classificationFilter, minRisk]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchHistory();
  };

  const handleExportCSV = () => {
    if (scans.length === 0) return;

    const headers = ['Probe ID', 'URL', 'Domain', 'Risk Score', 'Classification', 'ML Probability', 'Timestamp'];
    const rows = scans.map(s => [
      s.id,
      `"${s.url.replace(/"/g, '""')}"`,
      s.domain,
      s.risk_score,
      s.classification,
      s.ml_probability,
      new Date(s.created_at).toISOString()
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard_scan_history_${new Date().toISOString().substring(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getRiskBadge = (score: number) => {
    if (score >= 80) return { bg: 'bg-rose-500/10 text-rose-400 border-rose-500/30', label: 'CRITICAL' };
    if (score >= 60) return { bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30', label: 'HIGH' };
    if (score >= 40) return { bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30', label: 'MEDIUM' };
    if (score >= 20) return { bg: 'bg-blue-500/10 text-blue-400 border-blue-500/30', label: 'GUARDED' };
    return { bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', label: 'SAFE' };
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-cyber-border pb-5 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
            <History className="w-6 h-6 text-cyan-400" />
            <span>Scan Audit & Probe History</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Historical log of all URL security analyses stored in database with search, filter, and CSV export.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleExportCSV}
            className="px-4 py-2.5 rounded-xl bg-cyber-card border border-cyber-border hover:border-cyan-500/40 text-slate-300 text-xs font-mono flex items-center space-x-1.5 transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>
          <Link
            to="/scanner"
            className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 flex items-center space-x-1.5 transition-all"
          >
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5 space-y-4 font-mono text-xs">
        <form onSubmit={handleSearchSubmit} className="flex items-center space-x-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search history by target URL, domain name..."
              className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-cyber-bg border border-cyber-border text-slate-100 text-xs focus:border-cyan-500 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2.5 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-bold rounded-xl hover:bg-cyan-500/20 transition-colors"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-cyber-border">
          {/* Classification Filter Pills */}
          <div className="flex items-center space-x-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400 font-bold">Severity:</span>
            {['ALL', 'SAFE', 'GUARDED', 'SUSPICIOUS', 'PHISHING'].map((c) => (
              <button
                key={c}
                onClick={() => setClassificationFilter(c)}
                className={`px-3 py-1 rounded-lg text-[10px] font-bold transition-all ${
                  classificationFilter === c
                    ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                    : 'bg-cyber-bg border border-cyber-border text-slate-400 hover:text-slate-200'
                }`}
              >
                {c}
              </button>
            ))}
          </div>

          {/* Min Risk Slider */}
          <div className="flex items-center space-x-3">
            <span className="text-slate-400 font-bold">Min Risk: {minRisk}</span>
            <input
              type="range"
              min="0"
              max="100"
              step="10"
              value={minRisk}
              onChange={(e) => setMinRisk(Number(e.target.value))}
              className="accent-cyan-400 cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-5">
        {loading ? (
          <div className="py-12 flex flex-col items-center justify-center space-y-2">
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
            <span className="text-xs font-mono text-slate-400">Retrieving Scan Logs...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Probe ID</th>
                  <th className="py-3 px-4">Target URL</th>
                  <th className="py-3 px-4">Domain</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">ML Prob.</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-xs font-mono">
                {scans.length === 0 ? (
                  <tr>
                    <td className="py-8 px-4 text-center text-slate-400" colSpan={8}>
                      No security probe history matches criteria.
                    </td>
                  </tr>
                ) : (
                  scans.map((scan) => {
                    const badge = getRiskBadge(scan.risk_score);
                    return (
                      <tr key={scan.id} className="hover:bg-cyber-panel/40 transition-colors">
                        <td className="py-3 px-4 text-slate-500 text-[11px]">
                          #{scan.id.substring(0, 8)}
                        </td>
                        <td className="py-3 px-4 text-slate-200 truncate max-w-xs" title={scan.url}>
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
                        <td className="py-3 px-4 text-cyan-400 font-bold">
                          {(scan.ml_probability * 100).toFixed(1)}%
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px]">
                          {new Date(scan.created_at).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => setSelectedScanModal(scan)}
                            className="p-1.5 hover:bg-cyber-panel rounded text-cyan-400 transition-colors"
                            title="Inspect scan detail"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail Modal Drawer */}
      {selectedScanModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-cyber-card border border-cyber-border rounded-2xl max-w-2xl w-full p-6 space-y-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4">
              <div>
                <span className="text-[10px] font-mono text-slate-400">SCAN PROBE #{selectedScanModal.id.substring(0, 8)}</span>
                <h3 className="text-lg font-bold text-slate-100 font-mono truncate max-w-md">{selectedScanModal.url}</h3>
              </div>
              <button
                onClick={() => setSelectedScanModal(null)}
                className="p-2 hover:bg-cyber-panel rounded-lg text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 font-mono text-xs">
              <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xl">
                <span className="text-slate-400 block text-[10px]">RISK SCORE</span>
                <span className="text-xl font-bold text-rose-400">{selectedScanModal.risk_score}/100</span>
              </div>
              <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xl">
                <span className="text-slate-400 block text-[10px]">CLASSIFICATION</span>
                <span className="text-xl font-bold text-cyan-400">{selectedScanModal.classification}</span>
              </div>
            </div>

            <div className="space-y-2 font-mono text-xs">
              <h4 className="font-bold text-slate-300 uppercase">Risk Factor Indicators ({selectedScanModal.risk_factors.length})</h4>
              {selectedScanModal.risk_factors.map((rf, i) => (
                <div key={i} className="p-3 bg-cyber-bg border border-cyber-border rounded-lg text-slate-300">
                  <span className="font-bold text-rose-400">{rf.factor}</span> (+{rf.score_contribution} pts)
                  <p className="text-slate-400 text-[11px] mt-0.5">{rf.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
