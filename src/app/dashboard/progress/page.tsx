'use client';

import React from 'react';
import { 
  TrendingUp, 
  CheckCircle2, 
  AlertTriangle, 
  Wand2, 
  ArrowUpRight, 
  ShieldCheck, 
  History,
  Sparkles
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import { SECURITY_PROGRESS_HISTORY } from '@/lib/demo-data';

export default function SecurityProgressPage() {
  const { 
    activeApp, 
    vulnerabilities, 
    scoreComparison, 
    fixAllIssues, 
    clearAllData 
  } = useSecurity();

  const fixedCount = vulnerabilities.filter(v => v.status === 'fixed').length;
  const remainingCount = vulnerabilities.filter(v => v.status === 'confirmed').length;
  const scoreDiff = scoreComparison.after - scoreComparison.before;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
            <TrendingUp className="w-4 h-4" />
            <span>Continuous Posture Elevation</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Security Progress & Velocity
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Track remediation velocity, score jump benchmarks before and after applying secure code diffs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fixAllIssues}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/40 transition-all font-mono"
          >
            <Wand2 className="w-3.5 h-3.5" />
            <span>Simulate Developer Fixes</span>
          </button>
          <button
            onClick={clearAllData}
            className="px-3 py-2 rounded-xl text-xs font-mono text-slate-400 hover:text-white border border-slate-800"
          >
            Reset
          </button>
        </div>
      </div>

      {/* Before vs After Big Score Comparison Card */}
      <div className="p-8 rounded-2xl bg-gradient-to-r from-[#0d152c] via-[#0f1b3d] to-[#091024] border border-slate-800 shadow-2xl relative overflow-hidden">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-center text-center">
          
          {/* Before */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Before Security Fixes
            </span>
            <div className="text-5xl font-extrabold font-mono text-rose-400">
              {scoreComparison.before} <span className="text-sm font-normal text-slate-400">/ 100</span>
            </div>
            <p className="text-xs text-slate-400">
              Vulnerable to SQLi & exposed secrets
            </p>
          </div>

          {/* Delta Jump Indicator */}
          <div className="flex flex-col items-center justify-center space-y-2">
            <div className="w-14 h-14 rounded-full bg-emerald-500/20 border-2 border-emerald-500/50 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/20">
              <TrendingUp className="w-7 h-7" />
            </div>
            <div className="text-xl font-extrabold font-mono text-emerald-400">
              +{scoreDiff >= 0 ? scoreDiff : 0} Points Improvement
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Remediation verified by AST audit
            </span>
          </div>

          {/* After */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              After Code Refactors
            </span>
            <div className="text-5xl font-extrabold font-mono text-emerald-400">
              {scoreComparison.after} <span className="text-sm font-normal text-slate-400">/ 100</span>
            </div>
            <p className="text-xs text-slate-400">
              Hardened with parameterized queries & KMS
            </p>
          </div>

        </div>
      </div>

      {/* Velocity Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-xs font-mono text-slate-400 uppercase">Issues Resolved</span>
          <div className="text-3xl font-extrabold font-mono text-emerald-400">{fixedCount}</div>
          <p className="text-[11px] text-slate-500">Fixed via developer refactors</p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-xs font-mono text-slate-400 uppercase">Remaining Open</span>
          <div className="text-3xl font-extrabold font-mono text-rose-400">{remainingCount}</div>
          <p className="text-[11px] text-slate-500">Require code modifications</p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-xs font-mono text-slate-400 uppercase">Mean Time to Remediate</span>
          <div className="text-3xl font-extrabold font-mono text-cyan-400">1.8 Days</div>
          <p className="text-[11px] text-slate-500">65% faster with SecureLens AI</p>
        </div>

        <div className="p-5 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-xs font-mono text-slate-400 uppercase">Regression Defense</span>
          <div className="text-3xl font-extrabold font-mono text-purple-400">100%</div>
          <p className="text-[11px] text-slate-500">Zero reopened findings</p>
        </div>
      </div>

      {/* Historical Progress Timeline */}
      <div className="p-6 rounded-2xl bg-[#0b101e] border border-slate-800 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white font-mono flex items-center gap-2">
          <History className="w-4 h-4 text-cyber-cyan" />
          <span>Security Score Evolution Over Sprints</span>
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#070b14] text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
              <tr>
                <th className="p-3">Sprint Date</th>
                <th className="p-3">Security Score</th>
                <th className="p-3">Critical Issues</th>
                <th className="p-3">High Issues</th>
                <th className="p-3">Fixed Cumulative</th>
                <th className="p-3 text-right">Trend</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {SECURITY_PROGRESS_HISTORY.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40">
                  <td className="p-3 text-slate-200 font-bold">{item.date}</td>
                  <td className="p-3 font-extrabold text-cyan-400">{item.score} / 100</td>
                  <td className="p-3 text-rose-400 font-bold">{item.critical}</td>
                  <td className="p-3 text-orange-400">{item.high}</td>
                  <td className="p-3 text-emerald-400 font-bold">+{item.fixed_issues} fixed</td>
                  <td className="p-3 text-right text-emerald-400 font-bold">↑ Improving</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
