'use client';

import React, { useState } from 'react';
import { 
  Boxes, 
  AlertTriangle, 
  CheckCircle2, 
  ExternalLink, 
  ArrowUpRight, 
  Wand2, 
  ShieldCheck,
  Search
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';

export default function DependenciesPage() {
  const { dependencies, activeApp } = useSecurity();
  const [search, setSearch] = useState('');

  const appDeps = activeApp 
    ? dependencies.filter(d => d.application_id === activeApp.id) 
    : dependencies;

  const filtered = appDeps.filter(d =>
    d.package_name.toLowerCase().includes(search.toLowerCase()) ||
    (d.cve_id && d.cve_id.toLowerCase().includes(search.toLowerCase())) ||
    d.advisory_summary.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
            <Boxes className="w-4 h-4" />
            <span>Software Composition Analysis (SCA)</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Third-Party Dependency Risks & CVEs
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated auditing of open-source libraries against the National Vulnerability Database (NVD) and Open Source Vulnerabilities (OSV).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-3 py-1.5 rounded-lg bg-[#0e1424] border border-slate-800 text-slate-300">
            Total Audited: <strong className="text-white">{dependencies.length} Packages</strong>
          </span>
        </div>
      </div>

      {/* Search Bar */}
      <div className="p-4 rounded-xl bg-[#0b101e] border border-slate-800">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search package name (e.g. lodash, jsonwebtoken) or CVE..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#070b14] border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Dependencies Table or Clean State */}
      {filtered.length > 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-[#0b101e] overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0c111e] text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="p-4">Package</th>
                  <th className="p-4">Installed</th>
                  <th className="p-4">Recommended</th>
                  <th className="p-4">Severity</th>
                  <th className="p-4">CVE Identifier</th>
                  <th className="p-4">Advisory & Remediation Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filtered.map((dep) => {
                  const isCritical = dep.risk_level === 'critical';
                  const isHigh = dep.risk_level === 'high';

                  return (
                    <tr key={dep.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="p-4">
                        <span className="font-bold text-white block">{dep.package_name}</span>
                        <span className="text-[10px] text-slate-500">License: {dep.license}</span>
                      </td>
                      <td className="p-4 font-bold text-rose-400">
                        {dep.installed_version}
                      </td>
                      <td className="p-4 font-bold text-emerald-400">
                        {dep.recommended_version}
                      </td>
                      <td className="p-4">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                          isCritical
                            ? 'bg-rose-950/60 text-rose-300 border-rose-800/50'
                            : isHigh
                            ? 'bg-orange-950/60 text-orange-300 border-orange-800/50'
                            : 'bg-amber-950/60 text-amber-300 border-amber-800/50'
                        }`}>
                          {dep.risk_level}
                        </span>
                      </td>
                      <td className="p-4">
                        {dep.cve_id ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${dep.cve_id}`}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-cyber-cyan hover:underline"
                          >
                            <span>{dep.cve_id}</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        ) : (
                          <span className="text-slate-500">N/A</span>
                        )}
                      </td>
                      <td className="p-4 max-w-md">
                        <p className="text-slate-200">{dep.advisory_summary}</p>
                        <p className="text-[11px] text-cyan-300/80 mt-1">
                          ↳ Fix: {dep.upgrade_reason}
                        </p>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="p-10 rounded-2xl bg-[#0b101e] border border-slate-800 text-center space-y-3 font-mono">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
          <h3 className="text-sm font-semibold text-white">0 Vulnerable Packages Detected</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {dependencies.length === 0
              ? 'No dependencies are currently recorded for this application. To audit third-party open-source libraries, launch a Dependency SCA scan.'
              : 'No packages match your search filter.'}
          </p>
        </div>
      )}

      {/* Package Upgrade Guide */}
      <div className="p-5 rounded-xl bg-[#090e1c] border border-slate-800 space-y-2">
        <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Quick Remediation CLI Commands</span>
        </h3>
        <p className="text-xs text-slate-400">
          Run these package manager commands to patch vulnerable dependencies to recommended versions:
        </p>
        <pre className="p-3 rounded-lg bg-[#060912] border border-slate-800 text-xs font-mono text-cyan-200 overflow-x-auto">
          <code>
            npm install lodash@^4.17.21 axios@^1.7.4 jsonwebtoken@^9.0.2 express@^4.19.2
          </code>
        </pre>
      </div>
    </div>
  );
}
