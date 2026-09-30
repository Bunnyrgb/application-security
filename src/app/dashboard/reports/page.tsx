'use client';

import React from 'react';
import { useSecurity } from '@/context/SecurityContext';
import ExecutiveReportView from '@/components/reports/ExecutiveReportView';
import { FileText } from 'lucide-react';
import Link from 'next/link';

export default function ReportsPage() {
  const { activeScan, setActiveScan, scanHistory, activeApp } = useSecurity();

  const currentScan = activeScan || (scanHistory.length > 0 ? scanHistory[0] : null);

  if (!currentScan) {
    return (
      <div className="p-12 text-center rounded-2xl bg-[#0b101e] border border-slate-800 space-y-3 font-mono">
        <FileText className="w-10 h-10 text-slate-500 mx-auto" />
        <h3 className="text-sm font-semibold text-white">No Scan Audit Available</h3>
        <p className="text-xs text-slate-400">
          Run a security scan on <strong>{activeApp ? activeApp.name : 'an application'}</strong> to generate an executive audit report.
        </p>
        <Link
          href="/dashboard/new-scan"
          className="inline-block mt-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold bg-cyan-600 text-white"
        >
          Execute Security Scan
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {scanHistory.length > 1 && (
        <div className="no-print flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-xl bg-[#0b101e] border border-slate-800 text-xs font-mono">
          <span className="text-slate-400">Audit Report Archive ({scanHistory.length} Scans):</span>
          <select
            value={currentScan.id}
            onChange={(e) => {
              const selected = scanHistory.find(s => s.id === e.target.value);
              if (selected) setActiveScan(selected);
            }}
            className="px-3 py-1.5 bg-[#070b14] border border-slate-800 rounded-lg text-cyan-300 focus:outline-none focus:border-cyan-500 max-w-md truncate"
          >
            {scanHistory.map((s) => (
              <option key={s.id} value={s.id}>
                {s.application_name} — Score {s.score}/100 ({new Date(s.completed_at || s.started_at).toLocaleDateString()})
              </option>
            ))}
          </select>
        </div>
      )}
      <ExecutiveReportView scan={currentScan} />
    </div>
  );
}
