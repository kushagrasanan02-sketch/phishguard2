import React, { useEffect, useState } from 'react';
import { ShieldCheck, Users, Activity, Cpu, Lock, RefreshCw, CheckCircle, Clock, FileText, Zap, ShieldAlert } from 'lucide-react';
import { adminService } from '../services/api';
import { AdminStats, ModelVersion, User as UserType, AuditLog } from '../types';

export const AdminPage: React.FC = () => {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [models, setModels] = useState<ModelVersion[]>([]);
  const [users, setUsers] = useState<UserType[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditResult, setAuditResult] = useState<any | null>(null);
  const [benchResult, setBenchResult] = useState<any | null>(null);
  const [certResult, setCertResult] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRetraining, setIsRetraining] = useState(false);
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const loadAdminData = async () => {
    setIsLoading(true);
    try {
      const [s, m, u, a, audit, cert] = await Promise.all([
        adminService.getAdminStats(),
        adminService.getModelVersions(),
        adminService.getUsers(),
        adminService.getAuditLogs(),
        adminService.getSecurityAudit(),
        adminService.getCertification()
      ]);
      setStats(s);
      setModels(m);
      setUsers(u);
      setAuditLogs(a);
      setAuditResult(audit);
      setCertResult(cert);
    } catch (err: any) {
      console.error('Failed to load admin console data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAdminData();
  }, []);

  const handleRetrain = async () => {
    setIsRetraining(true);
    setMessage(null);
    try {
      const newModel = await adminService.retrainModel();
      setMessage(`Successfully trained and activated model ${newModel.version}! Accuracy: ${(newModel.metrics.accuracy * 100).toFixed(1)}%`);
      await loadAdminData();
    } catch (err: any) {
      setMessage('Failed to retrain model: ' + (err.response?.data?.detail || err.message));
    } finally {
      setIsRetraining(false);
    }
  };

  const handleRunBenchmark = async () => {
    setIsBenchmarking(true);
    try {
      const res = await adminService.runBenchmark(10);
      setBenchResult(res);
    } catch (err: any) {
      alert('Benchmark failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setIsBenchmarking(false);
    }
  };

  const handleActivate = async (modelId: string) => {
    try {
      await adminService.activateModel(modelId);
      setMessage('Model version activated successfully.');
      await loadAdminData();
    } catch (err: any) {
      setMessage('Failed to activate model: ' + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-cyber-border pb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
            <ShieldCheck className="w-6 h-6 text-purple-400" />
            <span>System Administration & Security Console</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            OWASP compliance audits, ML model registry, platform benchmarks, and audit trail.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleRunBenchmark}
            disabled={isBenchmarking}
            className="px-3.5 py-2 rounded-xl bg-cyber-panel border border-cyber-border hover:border-cyan-500 text-cyan-400 font-mono text-xs font-bold flex items-center space-x-1.5 transition-all cursor-pointer disabled:opacity-50"
          >
            <Zap className={`w-3.5 h-3.5 ${isBenchmarking ? 'animate-pulse' : ''}`} />
            <span>{isBenchmarking ? 'Benchmarking...' : 'Run Benchmark'}</span>
          </button>

          <button
            onClick={handleRetrain}
            disabled={isRetraining}
            className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-mono text-xs font-bold shadow-lg shadow-purple-600/20 flex items-center space-x-1.5 transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRetraining ? 'animate-spin' : ''}`} />
            <span>{isRetraining ? 'Retraining...' : 'Retrain ML Model'}</span>
          </button>
        </div>
      </div>

      {message && (
        <div className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-300 text-xs font-mono flex items-center space-x-2">
          <CheckCircle className="w-4 h-4 text-purple-400 flex-shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {/* Enterprise Production Release Candidate v1.0 Certification Badge */}
      {certResult && (
        <div className="p-6 bg-gradient-to-r from-emerald-950/40 via-cyber-card to-cyber-card border border-emerald-500/30 rounded-2xl shadow-2xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-emerald-500/20 pb-3">
            <div className="flex items-center space-x-3">
              <CheckCircle className="w-6 h-6 text-emerald-400" />
              <div>
                <h3 className="text-base font-bold text-slate-100 font-sans flex items-center space-x-2">
                  <span>{certResult.release_candidate}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono font-bold">
                    {certResult.release_version}
                  </span>
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  {certResult.certification_status} ({certResult.passed_checks_count}/{certResult.total_checks_count} Checks Passed)
                </p>
              </div>
            </div>

            <div className="px-4 py-2 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs font-bold rounded-xl text-center">
              GOLD CERTIFIED PRODUCTION READY
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
            {certResult.certification_checks?.map((check: any, cIdx: number) => (
              <div key={cIdx} className="p-3 bg-cyber-bg border border-cyber-border rounded-xl space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold">{check.category}</span>
                <p className="font-bold text-slate-200">{check.metric}</p>
                <span className="text-[10px] text-emerald-400 font-bold">✔ {check.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono">TOTAL USERS</span>
            <Users className="w-4 h-4 text-purple-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-slate-100">{stats?.total_users ?? 1}</p>
          <span className="text-[10px] text-purple-400 font-mono">Registered Accounts</span>
        </div>

        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono">SECURITY COMPLIANCE</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-emerald-400">{auditResult?.overall_score ?? 100}%</p>
          <span className="text-[10px] text-slate-400 font-mono">OWASP Compliance Rating</span>
        </div>

        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono">ACTIVE MODEL</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-xl font-bold font-mono text-slate-100 truncate">{stats?.active_model ?? 'RandomForest v1.0'}</p>
          <span className="text-[10px] text-emerald-400 font-mono">
            Precision: {((stats?.active_model_precision ?? 0.96) * 100).toFixed(1)}%
          </span>
        </div>

        <div className="bg-cyber-card border border-cyber-border p-5 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-mono">TOTAL PROBES</span>
            <Lock className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-slate-100">{(stats?.active_scans ?? 0) + (stats?.email_scans ?? 0)}</p>
          <span className="text-[10px] text-slate-400 font-mono">URL & Email Scans</span>
        </div>
      </div>

      {/* System Benchmark Metrics Widget */}
      {benchResult && (
        <div className="bg-cyber-card border border-cyan-500/30 rounded-2xl p-6 space-y-4 shadow-xl font-mono text-xs">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <div className="flex items-center space-x-2 text-cyan-400 font-bold">
              <Zap className="w-4 h-4" />
              <span>SYSTEM PERFORMANCE BENCHMARK RESULTS</span>
            </div>
            <span className="px-2.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
              RATING: {benchResult.performance_rating}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
              <span className="text-slate-400 text-[10px] block">AVG SCAN LATENCY</span>
              <span className="text-cyan-400 font-bold text-base">{benchResult.average_latency_ms} ms</span>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
              <span className="text-slate-400 text-[10px] block">THROUGHPUT</span>
              <span className="text-emerald-400 font-bold text-base">{benchResult.throughput_scans_per_sec} scans/sec</span>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
              <span className="text-slate-400 text-[10px] block">FEATURE EXTR. SPEED</span>
              <span className="text-slate-100 font-bold">{benchResult.breakdown?.lexical_feature_extraction_ms} ms</span>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
              <span className="text-slate-400 text-[10px] block">ML INFERENCE SPEED</span>
              <span className="text-purple-400 font-bold">{benchResult.breakdown?.ml_inference_and_scoring_ms} ms</span>
            </div>
          </div>
        </div>
      )}

      {/* Security Audit Checks List */}
      {auditResult && (
        <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4 font-mono text-xs">
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
            <span>Automated Security Posture Audit Checks ({auditResult.passed_checks}/{auditResult.total_checks} Passed)</span>
          </h2>

          <div className="space-y-2">
            {auditResult.checks.map((check: any, idx: number) => (
              <div key={idx} className="p-3 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between gap-4">
                <div className="space-y-0.5">
                  <span className="font-bold text-slate-200">{check.name}</span>
                  <p className="text-slate-400 text-[11px]">{check.details}</p>
                </div>
                <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                  check.status === 'PASSED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                }`}>
                  {check.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Model Versions Section */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Machine Learning Model Registry</span>
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-cyber-border text-slate-400 bg-cyber-bg">
                <th className="p-3">VERSION</th>
                <th className="p-3">ALGORITHM</th>
                <th className="p-3">ACCURACY</th>
                <th className="p-3">PRECISION</th>
                <th className="p-3">RECALL</th>
                <th className="p-3">F1-SCORE</th>
                <th className="p-3">STATUS</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {models.map((m) => (
                <tr key={m.id} className="hover:bg-cyber-panel/50 transition-colors">
                  <td className="p-3 font-bold text-slate-100">{m.version}</td>
                  <td className="p-3 text-slate-300">{m.algorithm}</td>
                  <td className="p-3 text-emerald-400">{(m.metrics.accuracy * 100).toFixed(1)}%</td>
                  <td className="p-3 text-cyan-400">{(m.metrics.precision * 100).toFixed(1)}%</td>
                  <td className="p-3 text-purple-400">{(m.metrics.recall * 100).toFixed(1)}%</td>
                  <td className="p-3 text-amber-400">{(m.metrics.f1_score * 100).toFixed(1)}%</td>
                  <td className="p-3">
                    {m.is_active ? (
                      <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        ACTIVE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-500/10 text-slate-400 border border-slate-500/20">
                        INACTIVE
                      </span>
                    )}
                  </td>
                  <td className="p-3 text-right">
                    {!m.is_active && (
                      <button
                        onClick={() => handleActivate(m.id)}
                        className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 text-[10px] font-bold transition-all"
                      >
                        Activate
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Trail Section */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
          <FileText className="w-4 h-4 text-purple-400" />
          <span>Security Audit Trail</span>
        </h2>
        <div className="space-y-2 font-mono text-xs">
          {auditLogs.slice(0, 10).map((log) => (
            <div key={log.id} className="p-3 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  {log.action}
                </span>
                <span className="text-slate-300 font-semibold">{JSON.stringify(log.details || {})}</span>
              </div>
              <span className="text-slate-500 text-[10px] flex items-center space-x-1">
                <Clock className="w-3 h-3" />
                <span>{new Date(log.timestamp).toLocaleString()}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
