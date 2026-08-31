import React, { useState } from 'react';
import { Bot, Send, X, ShieldAlert, CheckCircle2, ChevronRight, Terminal, RefreshCw } from 'lucide-react';
import { chatService } from '../services/api';

export const GuardAIChat: React.FC<{ isOpen: boolean; onClose: () => void }> = ({ isOpen, onClose }) => {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<Array<{ sender: 'user' | 'ai'; text: string; playbook?: string[] }>>([
    {
      sender: 'ai',
      text: 'GuardAI SOC Assistant online. Ask me about threat analysis, SSRF mitigation, EML email header analysis, or incident remediation playbooks.'
    }
  ]);
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userText = input.trim();
    setInput('');
    setMessages(prev => [...prev, { sender: 'user', text: userText }]);
    setLoading(true);

    try {
      const res = await chatService.analyzeQuery(userText);
      setMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: res.response,
          playbook: res.mitigation_playbook
        }
      ]);
    } catch (err: any) {
      setMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: 'Error communicating with GuardAI SOC Assistant. Please check system status.'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed bottom-4 right-4 w-96 max-w-[calc(100vw-2rem)] h-[550px] bg-cyber-card border border-cyber-border rounded-2xl shadow-2xl flex flex-col z-50 overflow-hidden font-mono text-xs">
      {/* Drawer Header */}
      <div className="p-4 bg-cyber-bg border-b border-cyber-border flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Bot className="w-5 h-5 text-cyan-400" />
          <span className="font-bold text-slate-100 font-sans">GuardAI SOC Assistant</span>
          <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold">
            v2.5
          </span>
        </div>

        <button
          onClick={onClose}
          className="p-1 rounded-lg text-slate-400 hover:text-slate-100 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Messages Stream */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4 bg-cyber-bg/50">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col space-y-1 ${
              m.sender === 'user' ? 'items-end' : 'items-start'
            }`}
          >
            <span className="text-[10px] text-slate-500 font-bold uppercase">
              {m.sender === 'user' ? 'You (Security Analyst)' : 'GuardAI Assistant'}
            </span>

            <div
              className={`p-3 rounded-xl leading-relaxed max-w-[90%] ${
                m.sender === 'user'
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'bg-cyber-card border border-cyber-border text-slate-200'
              }`}
            >
              {m.text}
            </div>

            {m.playbook && m.playbook.length > 0 && (
              <div className="mt-2 p-3 bg-cyber-bg border border-purple-500/30 rounded-xl space-y-1 max-w-[90%]">
                <div className="flex items-center space-x-1.5 text-purple-400 font-bold text-[11px] mb-1">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>RECOMMENDED SOC PLAYBOOK</span>
                </div>
                {m.playbook.map((step, sIdx) => (
                  <p key={sIdx} className="text-slate-300 text-[11px] leading-tight">
                    {step}
                  </p>
                ))}
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center space-x-2 text-cyan-400 italic text-[11px]">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            <span>GuardAI analyzing threat indicators...</span>
          </div>
        )}
      </div>

      {/* Input Box */}
      <form onSubmit={handleSend} className="p-3 bg-cyber-bg border-t border-cyber-border flex items-center space-x-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask GuardAI (e.g. 'How do I block SSRF?')..."
          className="flex-1 px-3 py-2 rounded-xl bg-cyber-card border border-cyber-border text-slate-100 text-xs focus:border-cyan-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="p-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-all disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};
