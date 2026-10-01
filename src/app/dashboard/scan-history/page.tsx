'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  History, 
  FileText, 
  ArrowUpRight, 
  CheckCircle2, 
  Radar, 
  Calendar,
  Layers,
  ArrowRightLeft,
  Check,
  AlertTriangle,
  RotateCcw,
  Sparkles,
  TrendingUp,
  X
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import { formatDate } from '@/lib/utils';
import { ScanComparison } from '@/types/security';

export default function ScanHistoryPage() {
  const { scanHistory, activeApp, setActiveScan, runNewScan } = useSecurity();

  const [selectedScan1, setSelectedScan1] = useState<string>('');
  const [selectedScan2, setSelectedScan2] = useState<string>('');
  const [comparisonResult, setComparisonResult] = useState<ScanComparison | null>(null);
  const [isComparing, setIsComparing] = useState(false);
  const [reScanningId, setReScanningId] = useState<string | null>(null);

  const handleCompare = async () => {
    if (!selectedScan1 || !selectedScan2 || selectedScan1 === selectedScan2) return;
    setIsComparing(true);

    const s1 = scanHistory.find(s => s.id === selectedScan1);
    const s2 = scanHistory.find(s => s.id === selectedScan2);

    if (s1 && s2) {
      try {
        const resp = await fetch('/api/scan/compare', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scan1: s1, scan2: s2 }),
        });
        if (resp.ok) {
          const data = await resp.json();
          setComparisonResult(data.comparison);
        }
      } catch {
        // Fallback local comparison
        const vulns1 = s1.vulnerabilities || [];
        const vulns2 = s2.vulnerabilities || [];
        const ids2 = new Set(vulns2.map(v => v.cwe_id));
        const ids1 = new Set(vulns1.map(v => v.cwe_id));

        const fixed = vulns1.filter(v => !ids2.has(v.cwe_id));
        const stillOpen = vulns2.filter(v => ids1.has(v.cwe_id));
        const newlyFound = vulns2.filter(v => !ids1.has(v.cwe_id));

        setComparisonResult({
          scanId1: s1.id,
          scanId2: s2.id,
          target: s2.target_identifier,
          date1: s1.completed_at || s1.started_at,
          date2: s2.completed_at || s2.started_at,
          scoreBefore: s1.score,
          scoreAfter: s2.score,
          fixedCount: fixed.length,
          stillOpenCount: stillOpen.length,
          newCount: newlyFound.length,
          falsePositiveCount: vulns2.filter(v => v.status === 'false_positive').length,
          fixedVulnerabilityIds: fixed.map(v => v.id),
          openVulnerabilityIds: stillOpen.map(v => v.id),
          newVulnerabilityIds: newlyFound.map(v => v.id),
        });
      }
    }
    setIsComparing(false);
  };

  const handleReScan = async (scan: any) => {
    setReScanningId(scan.id);
    await runNewScan(scan.scan_type, scan.target_identifier);
    setReScanningId(null);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <History className="w-4 h-4" />
            <span>Audit Trail & Historical Scans</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Scan History & Differential Comparison
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Review past assessments, compare baseline vs remediated scans, and verify risk score trends.
          </p>
        </div>

        <Link
          href="/dashboard/new-scan"
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-indigo-600 via-cyan-600 to-indigo-600 hover:opacity-90 shadow-md shadow-indigo-600/30 transition-all font-mono self-start sm:self-auto"
        >
          <Radar className="w-4 h-4 text-cyan-300" />
          <span>Launch New Scan</span>
        </Link>
      </div>

      {/* SECTION 29 & 31: SCAN COMPARISON ENGINE (BEFORE & AFTER SCAN) */}
      {scanHistory.length >= 2 && (
        <div className="p-6 rounded-2xl bg-gradient-to-r from-[#0d162a] via-[#0b1020] to-[#0d162a] border border-cyan-500/30 space-y-4 shadow-xl">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <h2 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <ArrowRightLeft className="w-4 h-4 text-cyan-400" />
                <span>Scan Differential Analyzer (Before vs After)</span>
              </h2>
              <p className="text-xs text-slate-400">
                Compare Scan 1 (baseline) against Scan 2 (after remediation) to verify resolved issues.
              </p>
            </div>

            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
              RE-SCAN VERIFICATION
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
            {/* Scan 1 Selector */}
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Baseline Scan (Scan 1):</label>
              <select
                value={selectedScan1}
                onChange={(e) => setSelectedScan1(e.target.value)}
                className="w-full p-2.5 rounded-xl bg-[#070b14] border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400"
              >
                <option value="">Select Baseline Scan...</option>
                {scanHistory.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.application_name} ({formatDate(s.completed_at || s.started_at)}) — Score {s.score}/100
                  </option>
                ))}
              </select>
            </div>

            {/* Scan 2 Selector */}
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Remediated Scan (Scan 2):</label>
              <select
                value={selectedScan2}
                onChange={(e) => setSelectedScan2(e.target.value)}
                className="w-full p-2.5 rounded-xl bg-[#070b14] border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400"
              >
                <option value="">Select Follow-up Scan...</option>
                {scanHistory.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.application_name} ({formatDate(s.completed_at || s.started_at)}) — Score {s.score}/100
                  </option>
                ))}
              </select>
            </div>

            {/* Compare Button */}
            <div className="flex items-end">
              <button
                disabled={!selectedScan1 || !selectedScan2 || selectedScan1 === selectedScan2 || isComparing}
                onClick={handleCompare}
                className="w-full p-2.5 rounded-xl font-bold bg-gradient-to-r from-cyan-500 to-indigo-600 text-slate-950 hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
              >
                <ArrowRightLeft className="w-4 h-4" />
                <span>{isComparing ? 'Comparing...' : 'Compare Scans'}</span>
              </button>
            </div>
          </div>

          {/* Comparison Result Card */}
          {comparisonResult && (
            <div className="mt-4 p-5 rounded-xl bg-[#080d1a] border border-slate-700 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="text-xs font-mono font-bold text-white flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Comparison Results for {comparisonResult.target}</span>
                </span>

                <button 
                  onClick={() => setComparisonResult(null)}
                  className="text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800/40 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">Fixed Issues</span>
                  <div className="text-xl font-bold text-emerald-300">
                    +{comparisonResult.fixedCount}
                  </div>
                  <span className="text-[10px] text-emerald-400">Resolved by developer</span>
                </div>

                <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-800/40 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">Still Open</span>
                  <div className="text-xl font-bold text-rose-300">
                    {comparisonResult.stillOpenCount}
                  </div>
                  <span className="text-[10px] text-rose-400">Require remediation</span>
                </div>

                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-800/40 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">New Findings</span>
                  <div className="text-xl font-bold text-amber-300">
                    {comparisonResult.newCount}
                  </div>
                  <span className="text-[10px] text-amber-400">Regressions found</span>
                </div>

                <div className="p-3 rounded-lg bg-purple-950/30 border border-purple-800/40 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">False Positives</span>
                  <div className="text-xl font-bold text-purple-300">
                    {comparisonResult.falsePositiveCount}
                  </div>
                  <span className="text-[10px] text-purple-400">Suppressed</span>
                </div>

                <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-800/40 space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase">Security Score</span>
                  <div className="text-xl font-bold text-cyan-300 flex items-center gap-1">
                    <span>{comparisonResult.scoreBefore}</span>
                    <span>→</span>
                    <span className={comparisonResult.scoreAfter >= comparisonResult.scoreBefore ? 'text-emerald-400' : 'text-rose-400'}>
                      {comparisonResult.scoreAfter}
                    </span>
                  </div>
                  <span className="text-[10px] text-cyan-400">Out of 100</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* History Table or Clean State */}
      {scanHistory.length > 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-[#0b101e] overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0c111e] text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="p-4">Application</th>
                  <th className="p-4">Scan Date</th>
                  <th className="p-4">Scan Type</th>
                  <th className="p-4">Security Score</th>
                  <th className="p-4">Critical</th>
                  <th className="p-4">High</th>
                  <th className="p-4">Medium</th>
                  <th className="p-4">Low</th>
                  <th className="p-4">Status</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scanHistory.map((scan) => {
                  const scoreColor = 
                    scan.score >= 80 ? 'text-emerald-400' :
                    scan.score >= 60 ? 'text-amber-400' : 'text-rose-400';

                  const isCurrentlyReScanning = reScanningId === scan.id;

                  return (
                    <tr key={scan.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="p-4 font-bold text-white">
                        {scan.application_name}
                        <span className="block text-[10px] text-slate-500 font-normal">
                          {scan.target_identifier}
                        </span>
                      </td>
                      <td className="p-4 text-slate-300">
                        {formatDate(scan.completed_at || scan.started_at)}
                      </td>
                      <td className="p-4 uppercase text-slate-400 text-[10px]">
                        {scan.scan_type.replace('_', ' ')}
                      </td>
                      <td className={`p-4 font-extrabold text-sm ${scoreColor}`}>
                        {scan.score} / 100
                      </td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40 font-bold">
                          {scan.critical_count}
                        </span>
                      </td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded bg-orange-950/60 text-orange-300 border border-orange-800/40 font-bold">
                          {scan.high_count}
                        </span>
                      </td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40 font-bold">
                          {scan.medium_count}
                        </span>
                      </td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-800/40 font-bold">
                          {scan.low_count}
                        </span>
                      </td>
                      <td className="p-4">
                        <span className="inline-flex items-center gap-1 text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Completed
                        </span>
                      </td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleReScan(scan)}
                            disabled={isCurrentlyReScanning}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                            title="Re-scan target to verify fixes"
                          >
                            <RotateCcw className={`w-3 h-3 text-cyan-400 ${isCurrentlyReScanning ? 'animate-spin' : ''}`} />
                            <span>Re-scan</span>
                          </button>

                          <Link
                            href="/dashboard/reports"
                            onClick={() => setActiveScan(scan)}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors"
                          >
                            <FileText className="w-3.5 h-3.5" />
                            <span>Report</span>
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="p-12 rounded-2xl bg-[#0b101e] border border-slate-800 text-center space-y-4 font-mono">
          <History className="w-12 h-12 text-slate-500 mx-auto" />
          <h3 className="text-sm font-semibold text-white">0 Historical Scans Recorded</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            You haven&apos;t executed any security scans yet. Launch your first audit to track security score evolutions over time.
          </p>
          <div className="pt-2">
            <Link
              href="/dashboard/new-scan"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 text-white"
            >
              <Radar className="w-4 h-4 text-cyan-200" />
              <span>Launch First Scan</span>
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
