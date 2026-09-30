'use client';

import React, { useState, useRef, useEffect } from 'react';
import { 
  Bot, 
  Send, 
  Sparkles, 
  User, 
  Copy, 
  Check, 
  ShieldCheck, 
  Terminal,
  CornerDownLeft,
  ChevronDown
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import { Vulnerability } from '@/types/security';

interface SecureLensAIChatProps {
  initialVulnId?: string;
}

export default function SecureLensAIChat({ initialVulnId }: SecureLensAIChatProps) {
  const { aiMessages, sendAIMessage, isAiThinking, vulnerabilities, activeApp } = useSecurity();
  const activeVulns = activeApp 
    ? vulnerabilities.filter(v => v.application_id === activeApp.id) 
    : vulnerabilities;

  const [input, setInput] = useState('');
  const [selectedVulnId, setSelectedVulnId] = useState<string>(initialVulnId || activeVulns[0]?.id || '');
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [aiMessages, isAiThinking]);

  useEffect(() => {
    if (initialVulnId) {
      setSelectedVulnId(initialVulnId);
    }
  }, [initialVulnId]);

  const handleSend = async (messageText?: string) => {
    const textToSend = messageText || input;
    if (!textToSend.trim() || isAiThinking) return;
    setInput('');
    await sendAIMessage(textToSend, selectedVulnId);
  };

  const copyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  const selectedVuln = vulnerabilities.find(v => v.id === selectedVulnId);

  const quickPrompts = [
    'Which issues should I fix first?',
    'Why is this vulnerability dangerous?',
    'How can I fix this?',
    'Show me a secure implementation.',
    'Explain this in simple English.',
    'Explain this vulnerability to my team.',
    'What security practices should I add?'
  ];

  return (
    <div className="flex flex-col h-[700px] rounded-xl border border-slate-800 bg-[#090d18] overflow-hidden shadow-2xl">
      {/* Top Header */}
      <div className="p-4 bg-[#0c111e] border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 p-[1px] flex items-center justify-center">
            <div className="w-full h-full bg-[#080d1a] rounded-[7px] flex items-center justify-center">
              <Bot className="w-4 h-4 text-cyber-cyan" />
            </div>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
              SecureLens AI Advisor
              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-sans">
                Context-Aware
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Directly grounded in your active AST findings and CVSS telemetry.
            </p>
          </div>
        </div>

        {/* Vulnerability Context Dropdown */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono hidden sm:inline">Active Context:</span>
          <select
            value={selectedVulnId}
            onChange={(e) => setSelectedVulnId(e.target.value)}
            className="text-xs font-mono bg-[#0e1424] border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 max-w-[220px] truncate"
          >
            {activeVulns.length > 0 ? (
              activeVulns.map(v => (
                <option key={v.id} value={v.id}>
                  [{v.severity.toUpperCase()}] {v.title}
                </option>
              ))
            ) : (
              <option value="">No vulnerabilities in scope</option>
            )}
          </select>
        </div>
      </div>

      {/* Message Stream */}
      <div className="flex-1 p-4 sm:p-6 overflow-y-auto space-y-4">
        {aiMessages.map((msg) => (
          <div
            key={msg.id}
            className={`flex gap-3 text-xs leading-relaxed ${
              msg.sender === 'user' ? 'justify-end' : 'justify-start'
            }`}
          >
            {msg.sender === 'assistant' && (
              <div className="w-7 h-7 rounded-lg bg-indigo-950/60 border border-indigo-700/50 flex items-center justify-center shrink-0 mt-0.5">
                <Sparkles className="w-3.5 h-3.5 text-cyber-cyan" />
              </div>
            )}

            <div
              className={`max-w-[85%] rounded-xl p-4 ${
                msg.sender === 'user'
                  ? 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-md'
                  : 'bg-[#0e1322] border border-slate-800/80 text-slate-200'
              }`}
            >
              {/* Message text with basic markdown formatting */}
              <div className="whitespace-pre-line space-y-2">
                {msg.content}
              </div>

              {/* Code Snippet if returned */}
              {msg.code_snippet && (
                <div className="mt-3 rounded-lg border border-slate-800 bg-[#060912] overflow-hidden">
                  <div className="flex items-center justify-between px-3 py-1.5 bg-[#090e1c] border-b border-slate-800 text-[11px] font-mono text-slate-400">
                    <span>{msg.code_snippet.language}</span>
                    <button
                      onClick={() => copyCode(msg.code_snippet!.code, msg.id)}
                      className="flex items-center gap-1 text-slate-400 hover:text-white"
                    >
                      {copiedCodeId === msg.id ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3 text-[11px] font-mono text-cyan-200 overflow-x-auto leading-relaxed">
                    <code>{msg.code_snippet.code}</code>
                  </pre>
                </div>
              )}

              {/* Suggested Follow-up Actions */}
              {msg.suggested_actions && msg.suggested_actions.length > 0 && (
                <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap gap-1.5">
                  {msg.suggested_actions.map((act, i) => (
                    <button
                      key={i}
                      onClick={() => handleSend(act)}
                      className="text-[10px] font-mono px-2 py-1 rounded bg-[#131b2e] hover:bg-slate-800 text-cyan-300 border border-slate-700/60 transition-colors"
                    >
                      + {act}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {msg.sender === 'user' && (
              <div className="w-7 h-7 rounded-lg bg-cyan-950/60 border border-cyan-700/50 flex items-center justify-center shrink-0 mt-0.5">
                <User className="w-3.5 h-3.5 text-cyan-300" />
              </div>
            )}
          </div>
        ))}

        {isAiThinking && (
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan animate-pulse">
            <Sparkles className="w-4 h-4 animate-spin" />
            <span>SecureLens AI is analyzing AST heuristics and crafting remediation...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts Bar */}
      <div className="px-4 py-2 bg-[#0a0f1d] border-t border-slate-800/80 flex items-center gap-1.5 overflow-x-auto text-[11px] font-mono text-slate-400 no-scrollbar">
        <span className="shrink-0 text-slate-500 font-bold">Quick Prompts:</span>
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(p)}
            className="shrink-0 px-2.5 py-1 rounded-md bg-[#0f1629] hover:bg-[#16213d] hover:text-white border border-slate-800 text-slate-300 transition-colors"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <div className="p-4 bg-[#0c111e] border-t border-slate-800">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={`Ask SecureLens AI about ${selectedVuln ? selectedVuln.title : 'security risks'}...`}
            className="flex-1 px-4 py-2.5 rounded-lg bg-[#070b14] border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            type="submit"
            disabled={!input.trim() || isAiThinking}
            className="px-4 py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 to-cyan-600 text-white font-mono text-xs font-semibold hover:opacity-90 transition-opacity disabled:opacity-40 flex items-center gap-1.5"
          >
            <span>Ask</span>
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
}
