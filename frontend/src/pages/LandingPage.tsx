import React from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Globe, 
  Mail, 
  ArrowRight, 
  Lock, 
  Cpu, 
  CheckCircle2, 
  ShieldCheck, 
  Zap, 
  Search, 
  BarChart3, 
  FileCheck2,
  AlertTriangle
} from 'lucide-react';

export const LandingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-cyber-bg text-slate-100 flex flex-col justify-between">
      {/* Hero Section */}
      <div className="relative overflow-hidden border-b border-cyber-border bg-gradient-to-b from-cyan-950/20 via-cyber-bg to-cyber-bg py-20 px-6 sm:px-12">
        <div className="max-w-5xl mx-auto text-center space-y-8 relative z-10">
          <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-semibold tracking-wide">
            <Zap className="w-3.5 h-3.5" />
            <span>PHISHGUARD AI PLATFORM GENERAL AVAILABILITY v1.0</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white leading-tight font-sans">
            Detect Phishing <br className="hidden sm:block" />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400">
              Before It Tricks You.
            </span>
          </h1>

          <p className="max-w-2xl mx-auto text-slate-300 text-base sm:text-lg leading-relaxed font-sans">
            AI-powered URL and email security analysis for identifying phishing indicators, suspicious domains, and malicious behavior in real-time.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
            <Link
              to="/scanner"
              className="w-full sm:w-auto px-8 py-3.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/25 flex items-center justify-center space-x-2 transition-all transform hover:-translate-y-0.5"
            >
              <Globe className="w-4 h-4" />
              <span>Analyze a URL</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
            
            <Link
              to="/email"
              className="w-full sm:w-auto px-8 py-3.5 rounded-xl bg-cyber-panel hover:bg-slate-800 text-slate-200 border border-cyber-border font-semibold text-sm flex items-center justify-center space-x-2 transition-all"
            >
              <Mail className="w-4 h-4 text-cyan-400" />
              <span>Analyze an Email</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Visual Pipeline Diagram Section */}
      <div className="max-w-6xl mx-auto px-6 py-16 w-full">
        <div className="text-center space-y-2 mb-12">
          <h2 className="text-xs font-mono font-bold uppercase tracking-widest text-cyan-400">Analysis Pipeline</h2>
          <p className="text-2xl font-bold text-slate-100">How PhishGuard AI Evaluates Threats</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative">
          {[
            { step: '01', title: 'URL / Email Input', desc: 'Normalized & sanitized input', icon: Search },
            { step: '02', title: 'Security Probes', desc: 'DNS, WHOIS, SSL, Redirects', icon: Globe },
            { step: '03', title: 'AI Detection Engine', desc: 'ML model classification', icon: Cpu },
            { step: '04', title: 'Risk Scoring', desc: 'Transparent 0-100 score', icon: BarChart3 },
            { step: '05', title: 'Security Report', desc: 'Actionable SOC report', icon: FileCheck2 },
          ].map((item, idx) => (
            <div key={idx} className="bg-cyber-card border border-cyber-border p-5 rounded-xl flex flex-col items-center text-center space-y-3 relative group hover:border-cyan-500/40 transition-colors">
              <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                STEP {item.step}
              </span>
              <div className="w-10 h-10 rounded-lg bg-cyber-panel flex items-center justify-center text-slate-300 group-hover:text-cyan-400 transition-colors">
                <item.icon className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-semibold text-slate-200">{item.title}</h3>
              <p className="text-xs text-slate-400 leading-normal">{item.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Key Features Grid */}
      <div className="border-t border-cyber-border bg-cyber-card/30 py-16 px-6">
        <div className="max-w-6xl mx-auto space-y-12">
          <div className="text-center space-y-2">
            <h2 className="text-xs font-mono font-bold uppercase tracking-widest text-cyan-400">Core Capabilities</h2>
            <p className="text-3xl font-bold text-slate-100">Multi-Layered Cyber Defense</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl space-y-3 hover:border-cyan-500/40 transition-all">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Globe className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-slate-200">Domain & SSL Inspection</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Extracts domain age, registrar telemetry, DNS records, HTTPS availability, and issuer certificate authenticity.
              </p>
            </div>

            <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl space-y-3 hover:border-cyan-500/40 transition-all">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <Cpu className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-slate-200">Machine Learning Classifier</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Interpretable Random Forest model predicting phishing probability based on structural & lexical feature vectors.
              </p>
            </div>

            <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl space-y-3 hover:border-cyan-500/40 transition-all">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-slate-200">Brand Impersonation Detection</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Levenshtein similarity & punycode evaluation targeting popular brands (PayPal, Microsoft, Google, Amazon).
              </p>
            </div>

            <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl space-y-3 hover:border-cyan-500/40 transition-all">
              <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-slate-200">Redirect & SSRF Safety Controls</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Controlled non-interactive HTTP multi-hop redirect tracing with RFC 1918 private IP and metadata blocking.
              </p>
            </div>

            <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl space-y-3 hover:border-cyan-500/40 transition-all">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Mail className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-slate-200">Email Header & EML Inspector</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Parses EML headers evaluating SPF/DKIM/DMARC authentication, reply-to mismatches, and embedded link risk.
              </p>
            </div>

            <div className="bg-cyber-card border border-cyber-border p-6 rounded-xl space-y-3 hover:border-cyan-500/40 transition-all">
              <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
                <BarChart3 className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-bold text-slate-200">Explainable Risk Scoring</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Transparent 0–100 risk score breakdown detailing exact contributing factors and security recommendations.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Security Disclaimer */}
      <div className="max-w-5xl mx-auto px-6 py-12 w-full">
        <div className="p-6 rounded-xl bg-slate-900/90 border border-cyber-border space-y-2 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <Lock className="w-6 h-6 text-cyan-400 flex-shrink-0" />
            <div>
              <h4 className="text-sm font-bold text-slate-200 font-mono">DEFENSIVE SECURITY RESEARCH DISCLAIMER</h4>
              <p className="text-xs text-slate-400">
                PhishGuard AI operates in a passive, non-interactive security mode. No credentials, form payloads, or untrusted scripts are ever submitted or executed during inspection probes.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-cyber-border bg-cyber-card py-8 px-6 text-center text-xs text-slate-500 font-mono">
        <p>© 2026 PhishGuard AI. Enterprise Phishing Detection & Security Risk Platform.</p>
      </footer>
    </div>
  );
};
