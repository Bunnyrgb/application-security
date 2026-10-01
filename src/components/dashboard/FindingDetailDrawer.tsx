'use client';

import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  FileCode, 
  Sparkles, 
  ArrowRight, 
  Copy, 
  Check, 
  ExternalLink, 
  CheckCircle2, 
  AlertTriangle, 
  Info,
  Bug,
  HelpCircle,
  Clock,
  Layers
} from 'lucide-react';
import { Vulnerability, TriageStatus } from '@/types/security';
import { getSeverityColor, getTriageBadge } from '@/lib/utils';
import { useSecurity } from '@/context/SecurityContext';

interface FindingDetailDrawerProps {
  vulnerability: Vulnerability | null;
  onClose: () => void;
}

export default function FindingDetailDrawer({ vulnerability, onClose }: FindingDetailDrawerProps) {
  const { updateVulnerabilityStatus } = useSecurity();
  const [activeTab, setActiveTab] = useState<'details' | 'remediation' | 'ai'>('details');
  const [codeTab, setCodeTab] = useState<'after' | 'before'>('after');
  const [copied, setCopied] = useState(false);
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [pendingStatus, setPendingStatus] = useState<TriageStatus>('confirmed');
  const [justificationReason, setJustificationReason] = useState('');

  if (!vulnerability) return null;

  const sevColor = getSeverityColor(vulnerability.severity);
  const triageBadge = getTriageBadge(vulnerability.status);

  const copyCode = (codeText?: string) => {
    if (!codeText) return;
    navigator.clipboard.writeText(codeText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const initiateStatusChange = (status: TriageStatus) => {
    if (status === 'false_positive' || status === 'accepted_risk') {
      setPendingStatus(status);
      setJustificationReason('');
      setShowStatusModal(true);
    } else {
      updateVulnerabilityStatus(vulnerability.id, status);
    }
  };

  const confirmStatusChange = () => {
    if (!justificationReason.trim()) return;
    updateVulnerabilityStatus(vulnerability.id, pendingStatus, justificationReason.trim());
    setShowStatusModal(false);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/75 backdrop-blur-sm flex justify-end animate-fadeIn">
      {/* Drawer Container */}
      <div className="w-full max-w-3xl bg-[#090d18] border-l border-slate-800 h-full flex flex-col shadow-2xl text-slate-200 overflow-hidden">
        
        {/* Header */}
        <div className="p-6 border-b border-slate-800 bg-[#0c1222] flex items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              {/* Severity */}
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase border ${sevColor.badge}`}>
                {vulnerability.severity}
              </span>

              {/* Confidence Badge */}
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase border ${
                vulnerability.confidence === 'high' 
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' 
                  : vulnerability.confidence === 'medium'
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  : 'bg-slate-700/30 text-slate-300 border-slate-600/40'
              }`}>
                Confidence: {vulnerability.confidence || 'Medium'}
              </span>

              {/* Status Badge */}
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono border ${triageBadge.bg}`}>
                Status: {vulnerability.status.toUpperCase()}
              </span>

              {/* CVSS */}
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-200">
                CVSS {vulnerability.cvss_score?.toFixed(1) || '7.5'}
              </span>

              {/* CWE */}
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-950/40 text-indigo-300 border border-indigo-800/40">
                {vulnerability.cwe_id}
              </span>
            </div>

            <h2 className="text-xl font-bold text-white tracking-tight">
              {vulnerability.title}
            </h2>

            <div className="flex items-center gap-2 text-xs font-mono text-cyan-300">
              <FileCode className="w-4 h-4 shrink-0" />
              <span className="truncate">{vulnerability.location}</span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center px-6 border-b border-slate-800 bg-[#080c16] text-xs font-mono">
          <button
            onClick={() => setActiveTab('details')}
            className={`py-3 px-4 font-semibold border-b-2 transition-all ${
              activeTab === 'details'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Finding Details & Evidence
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`py-3 px-4 font-semibold border-b-2 transition-all ${
              activeTab === 'remediation'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Developer Remediation & Diff
          </button>
          <button
            onClick={() => setActiveTab('ai')}
            className={`py-3 px-4 font-semibold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'ai'
                ? 'border-purple-400 text-purple-300 bg-purple-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            <span>AI Security Explainer</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {/* TAB 1: DETAILS & EVIDENCE */}
          {activeTab === 'details' && (
            <div className="space-y-6">
              
              {/* DATA FLOW DIAGRAM (CRITICAL SECTION 10 & 25) */}
              {vulnerability.data_flow && (
                <div className="p-4 rounded-xl bg-gradient-to-r from-[#0d162a] via-[#101c38] to-[#0d162a] border border-cyan-500/30 space-y-3">
                  <div className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>Verified Data-Flow Execution Trace</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                    {/* Source */}
                    <div className="p-3 rounded-lg bg-[#070a14] border border-rose-500/30 space-y-1">
                      <span className="text-[10px] text-rose-400 font-bold uppercase block">1. Source (Tainted Input)</span>
                      <div className="font-semibold text-rose-200 break-all">{vulnerability.data_flow.source}</div>
                    </div>

                    {/* Transformation */}
                    <div className="p-3 rounded-lg bg-[#070a14] border border-amber-500/30 space-y-1">
                      <span className="text-[10px] text-amber-400 font-bold uppercase block">2. Transformation</span>
                      <div className="font-semibold text-amber-200 break-all">{vulnerability.data_flow.transformation}</div>
                    </div>

                    {/* Sink */}
                    <div className="p-3 rounded-lg bg-[#070a14] border border-purple-500/30 space-y-1">
                      <span className="text-[10px] text-purple-400 font-bold uppercase block">3. Sink (DOM Execution)</span>
                      <div className="font-semibold text-purple-200 break-all">{vulnerability.data_flow.sink}</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Evidence Section */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-bold uppercase text-slate-400 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span>Technical Evidence & Detection Reasoning</span>
                </h4>
                <div className="p-4 rounded-xl bg-[#060912] border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
                  {vulnerability.evidence || 'Direct HTTP header and AST probe inspection.'}
                </div>
                {vulnerability.detection_logic && (
                  <p className="text-xs text-slate-400 italic">
                    Logic: {vulnerability.detection_logic}
                  </p>
                )}
              </div>

              {/* Potential Impact & Why It Matters */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/30 space-y-1.5">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Potential Impact</span>
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {vulnerability.potential_impact}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-900/30 space-y-1.5">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4" />
                    <span>Why It Matters</span>
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {vulnerability.why_it_matters}
                  </p>
                </div>
              </div>

              {/* Verification Steps */}
              {vulnerability.verification_steps && (
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold uppercase text-slate-400 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Developer Verification Protocol</span>
                  </h4>
                  <div className="p-4 rounded-xl bg-[#060912] border border-slate-800 text-xs text-slate-300 whitespace-pre-line leading-relaxed">
                    {vulnerability.verification_steps}
                  </div>
                </div>
              )}

              {/* References */}
              {vulnerability.references && vulnerability.references.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold uppercase text-slate-400">
                    Official Standards & References
                  </h4>
                  <ul className="space-y-1 text-xs font-mono">
                    {vulnerability.references.map((ref, idx) => (
                      <li key={idx}>
                        <a 
                          href={ref} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          <ExternalLink className="w-3 h-3" />
                          <span>{ref}</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: REMEDIATION & CODE DIFF */}
          {activeTab === 'remediation' && (
            <div className="space-y-6">
              <div className="p-4 rounded-xl bg-[#0d162a] border border-cyan-500/30 space-y-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300">
                  Recommended Remediation Strategy
                </span>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {vulnerability.recommended_fix}
                </p>
              </div>

              {(vulnerability.before_code || vulnerability.after_code) && (
                <div className="rounded-xl border border-slate-800 overflow-hidden bg-[#070a12] space-y-0">
                  <div className="flex items-center justify-between px-4 py-3 bg-[#0d1222] border-b border-slate-800">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setCodeTab('after')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                          codeTab === 'after'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        ✓ Hardened Code (Secure)
                      </button>
                      <button
                        onClick={() => setCodeTab('before')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                          codeTab === 'before'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        ✗ Vulnerable Code (Before)
                      </button>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono text-slate-400 uppercase">
                        {vulnerability.code_language || 'javascript'}
                      </span>
                      <button
                        onClick={() => copyCode(codeTab === 'after' ? vulnerability.after_code : vulnerability.before_code)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors flex items-center gap-1 text-xs font-mono"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copied ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  <pre className="p-4 text-xs font-mono overflow-x-auto text-slate-200 leading-relaxed max-h-96">
                    {codeTab === 'after' ? vulnerability.after_code : vulnerability.before_code}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: AI SECURITY EXPLAINER (SECTION 27) */}
          {activeTab === 'ai' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-800/40 flex items-center gap-3">
                <Sparkles className="w-5 h-5 text-purple-400 shrink-0" />
                <div className="text-xs text-purple-200">
                  <strong>SecureLens AI Audit Intelligence:</strong> Grounded strictly on observed technical evidence. No hallucinations or synthetic exploits.
                </div>
              </div>

              {vulnerability.ai_explanation ? (
                <div className="space-y-3 text-xs">
                  <div className="p-4 rounded-xl bg-[#0b1020] border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-cyan-400 uppercase block">1. What was found?</span>
                    <p className="text-slate-300 leading-relaxed">{vulnerability.ai_explanation.whatWasFound}</p>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b1020] border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-rose-400 uppercase block">2. Why is it a security concern?</span>
                    <p className="text-slate-300 leading-relaxed">{vulnerability.ai_explanation.whySecurityConcern}</p>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b1020] border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-indigo-400 uppercase block">3. How was it detected?</span>
                    <p className="text-slate-300 leading-relaxed">{vulnerability.ai_explanation.howDetected}</p>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b1020] border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-amber-400 uppercase block">4. How confident is the result?</span>
                    <p className="text-slate-300 leading-relaxed">{vulnerability.ai_explanation.howConfident}</p>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b1020] border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-purple-400 uppercase block">5. Could this be a false positive?</span>
                    <p className="text-slate-300 leading-relaxed">{vulnerability.ai_explanation.couldBeFalsePositive}</p>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b1020] border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-emerald-400 uppercase block">6. How should a developer fix it?</span>
                    <p className="text-slate-300 leading-relaxed">{vulnerability.ai_explanation.howToFix}</p>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0b1020] border border-slate-800 space-y-1">
                    <span className="font-mono font-bold text-teal-400 uppercase block">7. How can the developer verify the fix?</span>
                    <p className="text-slate-300 leading-relaxed">{vulnerability.ai_explanation.howToVerify}</p>
                  </div>
                </div>
              ) : (
                <div className="p-6 text-center text-xs text-slate-400">
                  Grounded AI analysis generated during live scanning. Consult the Assistant page for interactive queries.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions (Status Controls) */}
        <div className="p-4 border-t border-slate-800 bg-[#0c1222] flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs font-mono text-slate-400">
            Current Status: <strong className="text-white">{vulnerability.status.toUpperCase()}</strong>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => initiateStatusChange('fixed')}
              className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 transition-all flex items-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Mark Fixed</span>
            </button>

            <button
              onClick={() => initiateStatusChange('false_positive')}
              className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-purple-500/20 text-purple-300 border border-purple-500/40 hover:bg-purple-500/30 transition-all"
            >
              Mark False Positive
            </button>

            <button
              onClick={() => initiateStatusChange('accepted_risk')}
              className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30 transition-all"
            >
              Accept Risk
            </button>
          </div>
        </div>

        {/* Justification Modal for False Positive / Accepted Risk (Section 30 requirement) */}
        {showStatusModal && (
          <div className="fixed inset-0 z-60 bg-black/80 flex items-center justify-center p-4">
            <div className="w-full max-w-md bg-[#0e1526] border border-cyan-500/40 rounded-2xl p-6 space-y-4 shadow-2xl animate-scaleUp">
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Justification Required</span>
              </h3>
              <p className="text-xs text-slate-300">
                Company audit compliance requires a documented reason when marking a finding as{' '}
                <strong className="text-cyan-300">{pendingStatus.replace('_', ' ').toUpperCase()}</strong>.
              </p>

              <textarea
                value={justificationReason}
                onChange={(e) => setJustificationReason(e.target.value)}
                placeholder="Explain why this finding is classified as such (e.g. mitigated by edge WAF, internal trusted network, or planned Q4 deprecation)..."
                rows={3}
                className="w-full text-xs font-mono bg-[#070b14] border border-slate-700 rounded-xl p-3 text-slate-200 focus:outline-none focus:border-cyan-400"
              />

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  onClick={() => setShowStatusModal(false)}
                  className="px-4 py-2 rounded-lg text-xs font-mono text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  disabled={!justificationReason.trim()}
                  onClick={confirmStatusChange}
                  className="px-4 py-2 rounded-lg text-xs font-mono font-semibold bg-cyan-500 text-slate-950 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Confirm Status Change
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
