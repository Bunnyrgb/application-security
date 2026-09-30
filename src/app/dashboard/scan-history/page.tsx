'use client';

import React from 'react';
import Link from 'next/link';
import { 
  History, 
  FileText, 
  ArrowUpRight, 
  CheckCircle2, 
  Radar, 
  Calendar,
  Layers
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import { formatDate } from '@/lib/utils';

export default function ScanHistoryPage() {
  const { scanHistory, activeApp, setActiveScan } = useSecurity();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
            <History className="w-4 h-4" />
            <span>Audit Trail & Historical Scans</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Scan History
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Review previous scans, compare security score evolutions, and export executive audit reports.
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
                  <th className="p-4 text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scanHistory.map((scan) => {
                  const scoreColor = 
                    scan.score >= 80 ? 'text-emerald-400' :
                    scan.score >= 60 ? 'text-amber-400' : 'text-rose-400';

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
                        <Link
                          href="/dashboard/reports"
                          onClick={() => setActiveScan(scan)}
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors"
                        >
                          <FileText className="w-3.5 h-3.5" />
                          <span>View</span>
                        </Link>
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
