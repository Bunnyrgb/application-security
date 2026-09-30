'use client';

import React from 'react';
import { 
  Printer, 
  Download, 
  ShieldCheck, 
  Calendar, 
  Cpu, 
  Lock, 
  Boxes, 
  FileText, 
  AlertOctagon, 
  CheckCircle2,
  FileCheck
} from 'lucide-react';
import { Scan, Vulnerability, DependencyFinding } from '@/types/security';
import { formatDate, getScoreGrade, getSeverityColor } from '@/lib/utils';

interface ExecutiveReportViewProps {
  scan: Scan;
}

export default function ExecutiveReportView({ scan }: ExecutiveReportViewProps) {
  const grade = getScoreGrade(scan.score);

  const handlePrint = () => {
    window.print();
  };

  const criticals = scan.vulnerabilities.filter(v => v.severity === 'critical');
  const highs = scan.vulnerabilities.filter(v => v.severity === 'high');
  const mediums = scan.vulnerabilities.filter(v => v.severity === 'medium');
  const lows = scan.vulnerabilities.filter(v => v.severity === 'low');

  return (
    <div className="space-y-6">
      {/* Report Controls (Hidden in print) */}
      <div className="flex items-center justify-between no-print p-4 rounded-xl bg-[#0c101c] border border-slate-800">
        <div>
          <h2 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyber-cyan" />
            Executive Security Audit Report
          </h2>
          <p className="text-xs text-slate-400">
            Audit Document ID: SEC-AUD-{scan.id.slice(-8).toUpperCase()}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors font-mono"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-indigo-600 to-cyan-600 hover:opacity-90 text-white shadow-md shadow-indigo-600/30 transition-all font-mono"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF</span>
          </button>
        </div>
      </div>

      {/* The Printable Report Container */}
      <div id="security-report-document" className="p-8 sm:p-12 rounded-2xl bg-[#0b0f1c] border border-slate-800 text-slate-200 space-y-8 print:bg-white print:text-black print:p-0 print:border-none">
        
        {/* Cover Header */}
        <div className="border-b border-slate-800 pb-8 flex flex-col sm:flex-row sm:items-center justify-between gap-6 print:border-slate-300">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-6 h-6 text-cyber-cyan print:text-indigo-700" />
              <span className="text-xl font-bold font-mono tracking-tight text-white print:text-black">
                SecureLens Security Labs
              </span>
            </div>
            <h1 className="text-2xl font-extrabold text-white print:text-black tracking-tight">
              Application Vulnerability & Posture Assessment
            </h1>
            <p className="text-xs text-slate-400 print:text-slate-600 font-mono">
              Target: {scan.application_name} | Type: {scan.scan_type.replace('_', ' ').toUpperCase()}
            </p>
          </div>

          {/* Large Score Card */}
          <div className="p-4 rounded-xl bg-[#070a14] border border-slate-800 text-center sm:text-right print:bg-slate-100 print:border-slate-300">
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 print:text-slate-600">
              Overall Security Score
            </div>
            <div className={`text-4xl font-extrabold font-mono ${grade.color} print:text-black mt-1`}>
              {scan.score} <span className="text-sm font-normal text-slate-400 print:text-slate-600">/ 100</span>
            </div>
            <div className="text-xs font-semibold text-slate-300 print:text-slate-700 mt-1">
              {grade.label}
            </div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <div className="space-y-3">
          <h3 className="text-sm font-mono uppercase tracking-wider font-bold text-cyber-cyan print:text-indigo-800">
            1. Executive Summary
          </h3>
          <p className="text-xs text-slate-300 print:text-slate-800 leading-relaxed">
            SecureLens performed an automated security analysis on <strong>{scan.application_name}</strong> using static application security testing (SAST), software composition analysis (SCA), and credential exposure heuristics. The scan identified a total of <strong>{scan.vulnerabilities.length} security findings</strong>, including <strong>{scan.critical_count} Critical</strong>, <strong>{scan.high_count} High</strong>, and <strong>{scan.medium_count} Medium</strong> severity risks.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
            <div className="p-3 rounded-lg bg-[#070b16] border border-slate-800 print:bg-slate-50 print:border-slate-200">
              <span className="text-[11px] font-mono text-slate-400 print:text-slate-600">Critical Risks</span>
              <div className="text-xl font-bold font-mono text-rose-400 print:text-rose-700">{scan.critical_count}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#070b16] border border-slate-800 print:bg-slate-50 print:border-slate-200">
              <span className="text-[11px] font-mono text-slate-400 print:text-slate-600">High Risks</span>
              <div className="text-xl font-bold font-mono text-orange-400 print:text-orange-700">{scan.high_count}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#070b16] border border-slate-800 print:bg-slate-50 print:border-slate-200">
              <span className="text-[11px] font-mono text-slate-400 print:text-slate-600">Dependencies Audited</span>
              <div className="text-xl font-bold font-mono text-cyan-400 print:text-cyan-700">{scan.dependencies.length}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#070b16] border border-slate-800 print:bg-slate-50 print:border-slate-200">
              <span className="text-[11px] font-mono text-slate-400 print:text-slate-600">Scanner Engine</span>
              <div className="text-xs font-bold font-mono text-emerald-400 print:text-emerald-700 mt-1">{scan.scanner_version}</div>
            </div>
          </div>
        </div>

        {/* 2. Detected Stack & Scan Metadata */}
        <div className="space-y-3">
          <h3 className="text-sm font-mono uppercase tracking-wider font-bold text-cyber-cyan print:text-indigo-800">
            2. Technology Stack & Scan Metadata
          </h3>
          <div className="p-4 rounded-xl bg-[#080d1a] border border-slate-800 print:bg-slate-50 print:border-slate-200 text-xs">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div>
                <span className="text-slate-400 print:text-slate-600 block text-[11px] font-mono">Scan Date:</span>
                <span className="font-semibold text-slate-200 print:text-black">{formatDate(scan.completed_at || scan.started_at)}</span>
              </div>
              <div>
                <span className="text-slate-400 print:text-slate-600 block text-[11px] font-mono">Target Identifier:</span>
                <span className="font-semibold text-slate-200 print:text-black">{scan.target_identifier}</span>
              </div>
              <div>
                <span className="text-slate-400 print:text-slate-600 block text-[11px] font-mono">Detected Frameworks:</span>
                <span className="font-semibold text-slate-200 print:text-black">
                  {scan.detected_technologies.map(t => t.name).join(', ') || 'Node.js, Express'}
                </span>
              </div>
              <div>
                <span className="text-slate-400 print:text-slate-600 block text-[11px] font-mono">Compliance Framework:</span>
                <span className="font-semibold text-slate-200 print:text-black">OWASP Top 10 / CWE-25</span>
              </div>
            </div>
          </div>
        </div>

        {/* 3. Detailed Findings List */}
        <div className="space-y-4">
          <h3 className="text-sm font-mono uppercase tracking-wider font-bold text-cyber-cyan print:text-indigo-800">
            3. Vulnerability Findings & Remediation Guidance
          </h3>

          <div className="space-y-4">
            {scan.vulnerabilities.map((vuln, idx) => {
              const sev = getSeverityColor(vuln.severity);
              return (
                <div 
                  key={vuln.id}
                  className="p-4 rounded-xl bg-[#080d1a] border border-slate-800 print:bg-white print:border-slate-300 space-y-2 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-400">#{idx + 1}</span>
                      <h4 className="font-semibold text-white print:text-black text-sm">
                        {vuln.title}
                      </h4>
                    </div>
                    <div className="flex items-center gap-1.5 font-mono text-[11px]">
                      <span className={`px-2 py-0.5 rounded uppercase font-semibold border ${sev.badge}`}>
                        {vuln.severity}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 print:bg-slate-100 print:text-black">
                        CVSS {vuln.cvss_score}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-indigo-950/40 text-indigo-300 border border-indigo-800/40 print:text-indigo-900">
                        {vuln.cwe_id}
                      </span>
                    </div>
                  </div>

                  <div className="font-mono text-cyan-400 print:text-indigo-700 text-[11px]">
                    Location: {vuln.location}
                  </div>

                  <p className="text-slate-300 print:text-slate-800">
                    {vuln.description}
                  </p>

                  <div className="p-3 rounded-lg bg-[#0e1424] border border-slate-800 print:bg-slate-100 print:border-slate-200 mt-2 space-y-1">
                    <span className="font-mono font-semibold text-emerald-400 print:text-emerald-700 text-[11px] block">
                      Recommended Fix:
                    </span>
                    <p className="text-slate-300 print:text-slate-800 text-[11px]">
                      {vuln.recommended_fix}
                    </p>
                  </div>

                  {vuln.after_code && (
                    <div className="mt-2">
                      <span className="font-mono text-[10px] text-slate-400 uppercase block mb-1">
                        Secure Pattern ({vuln.code_language}):
                      </span>
                      <pre className="p-3 rounded-lg bg-[#050812] border border-slate-800 text-[11px] font-mono text-cyan-200 overflow-x-auto print:bg-slate-100 print:text-black print:border-slate-300">
                        <code>{vuln.after_code}</code>
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* 4. Dependency Vulnerabilities (SCA) */}
        {scan.dependencies.length > 0 && (
          <div className="space-y-3">
            <h3 className="text-sm font-mono uppercase tracking-wider font-bold text-cyber-cyan print:text-indigo-800">
              4. Software Composition Analysis (SCA) Risks
            </h3>
            <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-slate-300">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#090e1c] print:bg-slate-100 text-slate-400 print:text-slate-700 border-b border-slate-800 print:border-slate-300">
                  <tr>
                    <th className="p-3">Package</th>
                    <th className="p-3">Installed</th>
                    <th className="p-3">Recommended</th>
                    <th className="p-3">Risk</th>
                    <th className="p-3">CVE ID</th>
                    <th className="p-3">Remediation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 print:divide-slate-200">
                  {scan.dependencies.map((dep) => (
                    <tr key={dep.id} className="hover:bg-slate-900/40">
                      <td className="p-3 font-bold text-slate-200 print:text-black">{dep.package_name}</td>
                      <td className="p-3 text-rose-400 print:text-rose-700">{dep.installed_version}</td>
                      <td className="p-3 text-emerald-400 print:text-emerald-700">{dep.recommended_version}</td>
                      <td className="p-3 uppercase font-semibold text-rose-300">{dep.risk_level}</td>
                      <td className="p-3 text-cyan-300 print:text-indigo-700">{dep.cve_id}</td>
                      <td className="p-3 text-slate-400 print:text-slate-600 text-[11px]">{dep.upgrade_reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Report Footer */}
        <div className="pt-8 border-t border-slate-800 print:border-slate-300 text-xs text-slate-500 print:text-slate-600 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono">
          <div>
            Certified by SecureLens Automated Assessment Core v2.4
          </div>
          <div>
            ISO 27001 & SOC 2 Type II Aligned Scanning Principles
          </div>
        </div>

      </div>
    </div>
  );
}
