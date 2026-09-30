'use client';

import React from 'react';
import Link from 'next/link';
import { ShieldCheck, Lock, Terminal, Activity, Github, Twitter, Linkedin } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="border-t border-slate-800/80 bg-[#05070e] text-slate-400 text-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 md:py-16">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-8 md:gap-12">
          
          {/* Brand info */}
          <div className="md:col-span-2 space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-cyan-500 p-[1px]">
                <div className="w-full h-full bg-[#080d1a] rounded-[7px] flex items-center justify-center">
                  <ShieldCheck className="w-4 h-4 text-cyber-cyan" />
                </div>
              </div>
              <span className="text-lg font-bold text-white font-mono tracking-tight">
                SecureLens
              </span>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed max-w-sm">
              AI-assisted application security posture management. Automatically detect, explain, and remediate high-impact vulnerabilities before malicious adversaries exploit them.
            </p>
            <div className="flex items-center gap-2 pt-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                SecureLens Scanner Engine: Operational
              </span>
            </div>
          </div>

          {/* Product links */}
          <div>
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-200 font-semibold mb-4">
              Security Engine
            </h4>
            <ul className="space-y-2.5">
              <li><Link href="/dashboard/new-scan" className="hover:text-cyber-cyan transition-colors">SAST Code Review</Link></li>
              <li><Link href="/dashboard/dependencies" className="hover:text-cyber-cyan transition-colors">SCA Dependency Audit</Link></li>
              <li><Link href="/dashboard/new-scan" className="hover:text-cyber-cyan transition-colors">Secret & Credential Hunter</Link></li>
              <li><Link href="/dashboard/assistant" className="hover:text-cyber-cyan transition-colors">SecureLens AI Advisor</Link></li>
              <li><Link href="/dashboard/reports" className="hover:text-cyber-cyan transition-colors">Executive PDF Audits</Link></li>
            </ul>
          </div>

          {/* Standards & Compliance */}
          <div>
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-200 font-semibold mb-4">
              Standards & Mapping
            </h4>
            <ul className="space-y-2.5">
              <li className="text-slate-400 hover:text-slate-200">OWASP Top 10 (2021)</li>
              <li className="text-slate-400 hover:text-slate-200">CWE/SANS Top 25</li>
              <li className="text-slate-400 hover:text-slate-200">OWASP API Security Top 10</li>
              <li className="text-slate-400 hover:text-slate-200">SOC 2 Type II Alignment</li>
              <li className="text-slate-400 hover:text-slate-200">PCI-DSS 4.0 Readiness</li>
            </ul>
          </div>

          {/* Platform */}
          <div>
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-200 font-semibold mb-4">
              Platform & Legal
            </h4>
            <ul className="space-y-2.5">
              <li><Link href="/dashboard" className="hover:text-cyber-cyan transition-colors">Security Console</Link></li>
              <li><Link href="/dashboard/settings" className="hover:text-cyber-cyan transition-colors">Team & RBAC</Link></li>
              <li className="text-slate-400 hover:text-slate-200">Responsible Disclosure</li>
              <li className="text-slate-400 hover:text-slate-200">Privacy & Data Isolation</li>
              <li className="text-slate-400 hover:text-slate-200">Security Architecture</li>
            </ul>
          </div>
        </div>

        <div className="mt-12 pt-8 border-t border-slate-900 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div>
            © {new Date().getFullYear()} SecureLens Cyber Technologies Inc. All rights reserved.
          </div>
          <div className="flex items-center gap-6">
            <span className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              Isolated Non-Execution Scanner Sandboxes
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}
