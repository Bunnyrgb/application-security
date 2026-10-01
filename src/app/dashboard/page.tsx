'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  ShieldCheck, 
  Radar, 
  Wand2, 
  ArrowUpRight, 
  AlertOctagon, 
  ExternalLink, 
  GitBranch, 
  Boxes, 
  FileText, 
  Sparkles,
  Bot,
  Filter,
  CheckCircle2,
  Plus,
  Server
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import SecurityScoreGauge from '@/components/dashboard/SecurityScoreGauge';
import SeverityCards from '@/components/dashboard/SeverityCards';
import VulnerabilityCard from '@/components/dashboard/VulnerabilityCard';
import DashboardAnalyticsCharts from '@/components/dashboard/DashboardAnalyticsCharts';
import { SeverityLevel } from '@/types/security';
import { formatDate } from '@/lib/utils';

export default function DashboardPage() {
  const { 
    activeApp, 
    vulnerabilities, 
    dependencies, 
    scanHistory, 
    activeScan,
    fixAllIssues,
    clearAllData,
    loadDemoData 
  } = useSecurity();

  const [selectedSeverity, setSelectedSeverity] = useState<SeverityLevel | 'all'>('all');

  const appVulnerabilities = activeApp 
    ? vulnerabilities.filter(v => v.application_id === activeApp.id) 
    : vulnerabilities;

  const appDependencies = activeApp
    ? dependencies.filter(d => d.application_id === activeApp.id)
    : dependencies;

  const filteredVulnerabilities = appVulnerabilities.filter(v => {
    if (selectedSeverity === 'all') return true;
    return v.severity === selectedSeverity;
  });

  const confirmedIssues = appVulnerabilities.filter(v => v.status === 'confirmed').length;
  const fixedIssues = appVulnerabilities.filter(v => v.status === 'fixed').length;
  const falsePositivesCount = appVulnerabilities.filter(v => v.status === 'false_positive').length;
  const acceptedRisksCount = appVulnerabilities.filter(v => v.status === 'accepted_risk').length;
  const urlsCount = activeScan?.urls_discovered_count || (activeApp?.repository_url ? 12 : 8);
  const endpointsCount = activeScan?.endpoints_discovered_count || (activeScan?.discovered_endpoints?.length || 6);
  const techCount = activeApp?.technology_stack?.length || activeScan?.detected_technologies?.length || 4;
  const scanDuration = activeScan?.scan_duration_ms ? `${(activeScan.scan_duration_ms / 1000).toFixed(1)}s` : '2.4s';

  // Fresh State: When no target application exists yet
  if (!activeApp) {
    return (
      <div className="space-y-6">
        <div className="p-10 sm:p-14 rounded-3xl bg-gradient-to-br from-[#0c142e] via-[#080d20] to-[#040714] border border-cyan-500/25 shadow-2xl text-center space-y-6 neon-border">
          <div className="w-16 h-16 rounded-2xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400 mx-auto shadow-lg shadow-cyan-500/15">
            <Server className="w-8 h-8" />
          </div>

          <div className="max-w-xl mx-auto space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-300">
              <span>FRESH AUDIT WORKSPACE INITIALIZED</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Ready to Audit Your Application
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
              SecureLens is currently clean. Register an application target in the Admin Panel or execute a security scan with your custom source code.
            </p>
          </div>

          <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link
              href="/dashboard/admin"
              className="w-full sm:w-auto px-6 py-3 rounded-xl font-mono text-xs font-semibold text-white bg-gradient-to-r from-cyan-500 to-indigo-600 hover:opacity-95 shadow-lg shadow-cyan-500/25 flex items-center justify-center gap-2"
            >
              <Plus className="w-4 h-4" />
              <span>Create Application in Admin Panel</span>
            </Link>

            <Link
              href="/dashboard/new-scan"
              className="w-full sm:w-auto px-6 py-3 rounded-xl font-mono text-xs font-semibold text-slate-200 bg-[#0c1124] hover:bg-[#121936] border border-slate-700/80 hover:border-cyan-500/50 flex items-center justify-center gap-2"
            >
              <Radar className="w-4 h-4 text-cyan-400" />
              <span>Direct Code Scan</span>
            </Link>

            <button
              onClick={loadDemoData}
              className="w-full sm:w-auto px-5 py-3 rounded-xl font-mono text-xs font-semibold text-slate-400 hover:text-white border border-slate-800 hover:bg-slate-800/60"
            >
              Load Sample Demo Project
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Top Banner: Application Identity & Actions */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0c142c] via-[#091024] to-[#060c1d] border border-cyan-500/20 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-6 neon-border">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 uppercase tracking-wider font-semibold">
              ● {activeApp.environment}
            </span>
            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
              {activeApp.technology_stack.map(t => t.name).join(' • ') || 'HTML5 • Node.js'}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Last audit: {formatDate(activeApp.last_scanned_at)}
            </span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-sans">
            {activeApp.name}
          </h1>

          {activeApp.repository_url && (
            <a
              href={activeApp.repository_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-300 transition-colors font-mono"
            >
              <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
              <span>{activeApp.repository_url}</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>

        {/* Action CTAs */}
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={fixAllIssues}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/40 shadow-sm transition-all font-mono"
          >
            <Wand2 className="w-4 h-4 text-emerald-400" />
            <span>Apply Fixes (Score 98)</span>
          </button>

          <Link
            href="/dashboard/new-scan"
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-cyan-500 via-indigo-600 to-cyan-500 hover:opacity-95 shadow-lg shadow-cyan-500/20 transition-all font-mono"
          >
            <Radar className="w-4 h-4 text-cyan-200" />
            <span>New Security Scan</span>
          </Link>
        </div>
      </div>

      {/* SECTION 2: OPERATIONAL METRICS RIBBON */}
      <div className="p-4 rounded-xl bg-[#080d1a] border border-slate-800 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 text-xs font-mono">
        <div className="space-y-0.5">
          <span className="text-slate-500 text-[10px] uppercase">Security Score</span>
          <div className="text-base font-bold text-cyan-400">{activeApp.current_score} / 100</div>
        </div>
        <div className="space-y-0.5">
          <span className="text-slate-500 text-[10px] uppercase">Open Vulnerabilities</span>
          <div className="text-base font-bold text-rose-400">{confirmedIssues} open</div>
        </div>
        <div className="space-y-0.5">
          <span className="text-slate-500 text-[10px] uppercase">Fixed / Resolved</span>
          <div className="text-base font-bold text-emerald-400">{fixedIssues} fixed</div>
        </div>
        <div className="space-y-0.5">
          <span className="text-slate-500 text-[10px] uppercase">False Positives</span>
          <div className="text-base font-bold text-purple-400">{falsePositivesCount} filtered</div>
        </div>
        <div className="space-y-0.5">
          <span className="text-slate-500 text-[10px] uppercase">Accepted Risks</span>
          <div className="text-base font-bold text-amber-400">{acceptedRisksCount} logged</div>
        </div>
        <div className="space-y-0.5">
          <span className="text-slate-500 text-[10px] uppercase">Surface Endpoints</span>
          <div className="text-base font-bold text-indigo-400">{endpointsCount} found</div>
        </div>
        <div className="space-y-0.5">
          <span className="text-slate-500 text-[10px] uppercase">Scan Duration</span>
          <div className="text-base font-bold text-slate-300">{scanDuration}</div>
        </div>
      </div>

      {/* Analytics Charts Component */}
      <DashboardAnalyticsCharts 
        vulnerabilities={appVulnerabilities} 
        activeScan={activeScan} 
        score={activeApp.current_score} 
        scanHistory={scanHistory}
      />

      {/* Main Scorecard & Posture Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scorecard Widget */}
        <div className="lg:col-span-2 p-6 rounded-2xl glass-card space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <h2 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold">
                Security Posture Score
              </h2>
              <span className="text-xs text-slate-400">
                Calculated dynamically from active vulnerabilities and dependency CVEs.
              </span>
            </div>

            <Link
              href="/dashboard/progress"
              className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1 font-semibold"
            >
              <span>Score History</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <SecurityScoreGauge
            score={activeApp.current_score}
            previousScore={activeApp.previous_score}
            breakdown={activeScan?.score_breakdown}
            size="lg"
          />
        </div>

        {/* AI Co-Pilot Summary Widget */}
        <div className="p-6 rounded-2xl glass-card flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyan-400">
              <Bot className="w-4 h-4 text-cyan-400" />
              <span>SECURELENS AI CO-PILOT</span>
            </div>
            <h3 className="text-sm font-semibold text-white">
              Remediation Action Plan
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              {activeApp.critical_count > 0 ? (
                <>
                  <strong className="text-rose-400 font-mono">{activeApp.critical_count} Critical vulnerabilities</strong> require immediate triage. Fix the SQL injection and exposed secrets first.
                </>
              ) : (
                <>
                  All critical security threats have been resolved. Excellent application security hygiene!
                </>
              )}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#030612]/90 border border-slate-800 text-xs space-y-2 font-mono">
            <div className="flex justify-between text-slate-400 text-[11px]">
              <span>Active Issues:</span>
              <span className="text-white font-bold">{confirmedIssues}</span>
            </div>
            <div className="flex justify-between text-slate-400 text-[11px]">
              <span>Remediated Issues:</span>
              <span className="text-emerald-400 font-bold">{fixedIssues}</span>
            </div>
            <div className="flex justify-between text-slate-400 text-[11px]">
              <span>Dependencies Audited:</span>
              <span className="text-cyan-400 font-bold">{appDependencies.length} packages</span>
            </div>
          </div>

          <Link
            href="/dashboard/assistant"
            className="w-full py-2.5 px-3 rounded-xl text-xs font-mono font-semibold text-center bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors flex items-center justify-center gap-2"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Consult AI Security Analyst</span>
          </Link>
        </div>
      </div>

      {/* Severity Breakdown Metric Cards */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
            Vulnerability Breakdown by Severity
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            Click any card to filter findings below
          </span>
        </div>

        <SeverityCards
          critical={activeApp.critical_count}
          high={activeApp.high_count}
          medium={activeApp.medium_count}
          low={activeApp.low_count}
          info={activeApp.info_count}
          selectedSeverity={selectedSeverity}
          onSelectSeverity={setSelectedSeverity}
        />
      </div>

      {/* Detected Vulnerabilities List */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <span>Security Findings</span>
              <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
                {filteredVulnerabilities.length} displayed
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Expand any issue to inspect attack vectors, impact, and drop-in code refactors.
            </p>
          </div>

          {selectedSeverity !== 'all' && (
            <button
              onClick={() => setSelectedSeverity('all')}
              className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1 self-start"
            >
              <span>Clear Filter ({selectedSeverity.toUpperCase()})</span>
            </button>
          )}
        </div>

        {/* Vulnerability Cards */}
        <div className="space-y-3">
          {filteredVulnerabilities.length > 0 ? (
            filteredVulnerabilities.map((vuln) => (
              <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
            ))
          ) : (
            <div className="p-8 text-center rounded-2xl glass-card text-slate-400 text-xs font-mono space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <div>No security findings matching this severity filter.</div>
              <button
                onClick={() => setSelectedSeverity('all')}
                className="text-cyan-400 hover:underline"
              >
                Reset to View All
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Software Composition Analysis Quick Table */}
      {dependencies.length > 0 && (
        <div className="p-6 rounded-2xl glass-card space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Boxes className="w-4 h-4 text-cyan-400" />
                <span>Software Composition Analysis (SCA) Overview</span>
              </h2>
              <p className="text-xs text-slate-400">
                Known CVE advisories identified in direct and transitive dependencies.
              </p>
            </div>

            <Link
              href="/dashboard/dependencies"
              className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1 font-semibold"
            >
              <span>View All Dependencies</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#030612]/90 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3">Package</th>
                  <th className="p-3">Installed</th>
                  <th className="p-3">Recommended</th>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Vulnerability / Advisory</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {dependencies.slice(0, 3).map((dep) => (
                  <tr key={dep.id} className="hover:bg-slate-900/50">
                    <td className="p-3 font-bold text-slate-200">{dep.package_name}</td>
                    <td className="p-3 text-rose-400">{dep.installed_version}</td>
                    <td className="p-3 text-emerald-400">{dep.recommended_version}</td>
                    <td className="p-3 uppercase font-semibold text-rose-300">
                      <span className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/40 text-[10px]">
                        {dep.risk_level}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300">{dep.advisory_summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
