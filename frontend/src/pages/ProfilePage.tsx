import React, { useEffect, useState } from 'react';
import { Key, User as UserIcon, Shield, Copy, Check, Trash2, Plus, Lock, AlertCircle, Clock } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { apiKeyService } from '../services/api';
import { APIKeyItem, APIKeyCreatedItem } from '../types';

export const ProfilePage: React.FC = () => {
  const { user } = useAuth();
  const [keys, setKeys] = useState<APIKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [keyName, setKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState<APIKeyCreatedItem | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchKeys = async () => {
    setLoading(true);
    try {
      const data = await apiKeyService.listKeys();
      setKeys(data);
    } catch (err: any) {
      console.error('Failed to load API keys:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyName.trim()) {
      setError('Please provide a key description name.');
      return;
    }
    setError(null);
    try {
      const newKey = await apiKeyService.createKey(keyName);
      setCreatedKey(newKey);
      setKeyName('');
      await fetchKeys();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create API key.');
    }
  };

  const handleRevokeKey = async (id: string) => {
    try {
      await apiKeyService.revokeKey(id);
      await fetchKeys();
    } catch (err: any) {
      setError('Failed to revoke API key.');
    }
  };

  const handleCopyKey = () => {
    if (!createdKey) return;
    navigator.clipboard.writeText(createdKey.api_key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="border-b border-cyber-border pb-5">
        <h1 className="text-2xl font-bold text-slate-100 font-sans flex items-center space-x-3">
          <UserIcon className="w-6 h-6 text-cyan-400" />
          <span>Security Analyst Profile & API Keys</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Manage security analyst profile parameters and programmatic API keys for SIEM / CLI integrations.
        </p>
      </div>

      {/* User Information Card */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Account Credentials</span>
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xl">
            <span className="text-slate-400 block text-[10px]">ANALYST EMAIL</span>
            <span className="text-slate-100 font-bold">{user?.email || 'admin@phishguard.sec'}</span>
          </div>
          <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xl">
            <span className="text-slate-400 block text-[10px]">FULL NAME</span>
            <span className="text-slate-100 font-bold">{user?.full_name || 'Lead Security Analyst'}</span>
          </div>
          <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xl">
            <span className="text-slate-400 block text-[10px]">SYSTEM ROLE</span>
            <span className="text-purple-400 font-bold">{user?.role || 'ADMIN'}</span>
          </div>
        </div>
      </div>

      {/* API Key Creator & List */}
      <div className="bg-cyber-card border border-cyber-border rounded-2xl p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-cyber-border pb-4">
          <div>
            <h2 className="text-sm font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <Key className="w-4 h-4 text-purple-400" />
              <span>Programmatic API Access Keys</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Authenticate automated URL scans via HTTP header: <code className="text-cyan-400">X-API-Key: pg_live_...</code>
            </p>
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center space-x-2">
            <AlertCircle className="w-4 h-4" />
            <span>{error}</span>
          </div>
        )}

        {/* Secret Key Display Modal Banner when created */}
        {createdKey && (
          <div className="p-5 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-slate-100 font-mono text-xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-300">🔑 API Key Secret Generated (Copy Now — Shown Only Once!)</span>
              <button
                onClick={() => setCreatedKey(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                Dismiss
              </button>
            </div>
            <div className="p-3 bg-cyber-bg border border-cyber-border rounded-xl flex items-center justify-between">
              <span className="text-cyan-400 font-bold text-sm tracking-wide select-all">{createdKey.api_key}</span>
              <button
                onClick={handleCopyKey}
                className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 transition-all cursor-pointer"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                <span>{copied ? 'Copied!' : 'Copy Key'}</span>
              </button>
            </div>
          </div>
        )}

        {/* Generate Form */}
        <form onSubmit={handleCreateKey} className="flex items-center space-x-3 font-mono text-xs">
          <input
            type="text"
            value={keyName}
            onChange={(e) => setKeyName(e.target.value)}
            placeholder="Key Description (e.g., SIEM Production Collector, CLI Tool)..."
            className="flex-1 p-3 rounded-xl bg-cyber-bg border border-cyber-border text-slate-100 focus:border-cyan-500 focus:outline-none"
          />
          <button
            type="submit"
            className="px-5 py-3 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold flex items-center space-x-2 transition-all cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Generate Key</span>
          </button>
        </form>

        {/* Keys Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-cyber-border text-slate-400 bg-cyber-bg">
                <th className="p-3">KEY NAME</th>
                <th className="p-3">PREFIX</th>
                <th className="p-3">CREATED DATE</th>
                <th className="p-3">STATUS</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {keys.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-6 text-center text-slate-500">
                    No active API Keys generated yet. Create one above for programmatic access.
                  </td>
                </tr>
              ) : (
                keys.map((k) => (
                  <tr key={k.id} className="hover:bg-cyber-panel/50 transition-colors">
                    <td className="p-3 font-bold text-slate-100">{k.name}</td>
                    <td className="p-3 text-cyan-400 font-bold">{k.key_prefix}...</td>
                    <td className="p-3 text-slate-400">{new Date(k.created_at).toLocaleDateString()}</td>
                    <td className="p-3">
                      {k.is_active ? (
                        <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          ACTIVE
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                          REVOKED
                        </span>
                      )}
                    </td>
                    <td className="p-3 text-right">
                      {k.is_active && (
                        <button
                          onClick={() => handleRevokeKey(k.id)}
                          className="p-1.5 rounded hover:bg-rose-500/20 text-rose-400 transition-colors"
                          title="Revoke Key"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
