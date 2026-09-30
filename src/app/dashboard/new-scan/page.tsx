'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { 
  Radar, 
  Terminal, 
  CheckCircle2, 
  ArrowRight, 
  FileText, 
  Eye, 
  RotateCcw,
  Sparkles,
  Lock,
  Layers
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import ScanWorkflow from '@/components/scanner/ScanWorkflow';
import LiveScanTerminal from '@/components/scanner/LiveScanTerminal';
import { ScanType } from '@/types/security';

export default function NewScanPage() {
  const router = useRouter();
  const { 
    runNewScan, 
    isScanning, 
    scanProgress, 
    currentStepMessage, 
    telemetryLogs, 
    activeScan,
    activeApp 
  } = useSecurity();

  const [hasCompletedScan, setHasCompletedScan] = useState(false);

  const handleStartScan = async (type: ScanType, target: string, content?: string) => {
    setHasCompletedScan(false);
    await runNewScan(type, target, content);
    setHasCompletedScan(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
            <Radar className="w-4 h-4" />
            <span>Automated Analysis Pipeline</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            New Security Scan
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Analyze source code, dependencies, configuration files, APIs, and credentials with zero runtime execution risk.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-3 py-1 rounded-lg bg-[#0e1424] border border-slate-800 text-slate-300">
            Target Engine: <strong className="text-cyan-300">Auto-Resolves New Target per URL / Code</strong>
          </span>
        </div>
      </div>

      {/* If currently scanning or just completed, show the live terminal */}
      {(isScanning || hasCompletedScan) && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyber-cyan" />
              <span>Real-Time Scanner Telemetry</span>
            </h2>

            {hasCompletedScan && !isScanning && (
              <span className="text-xs font-mono text-emerald-400 font-bold flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                Security Scan Completed Successfully!
              </span>
            )}
          </div>

          <LiveScanTerminal
            progress={scanProgress}
            currentStepMessage={currentStepMessage}
            telemetryLogs={telemetryLogs}
            isScanning={isScanning}
          />

          {/* Post-Scan Completion Actions */}
          {hasCompletedScan && !isScanning && activeScan && (
            <div className="p-6 rounded-2xl bg-gradient-to-r from-emerald-950/30 via-[#0d162a] to-emerald-950/30 border border-emerald-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4 animate-fadeIn">
              <div className="space-y-1">
                <div className="text-xs font-mono text-emerald-300 font-bold uppercase tracking-wider">
                  ✓ Assessment Finalized
                </div>
                <div className="text-lg font-bold text-white font-mono">
                  Calculated Security Score: <span className="text-cyber-cyan">{activeScan.score} / 100</span>
                </div>
                <p className="text-xs text-slate-300">
                  Identified <strong>{activeScan.critical_count} Critical</strong>, <strong>{activeScan.high_count} High</strong>, and <strong>{activeScan.medium_count} Medium</strong> issues.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <Link
                  href="/dashboard/reports"
                  className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors font-mono"
                >
                  <FileText className="w-3.5 h-3.5 text-cyan-400" />
                  <span>View Security Report</span>
                </Link>

                <Link
                  href="/dashboard"
                  className="flex items-center gap-1.5 px-5 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-indigo-600 via-cyan-600 to-indigo-600 hover:opacity-90 shadow-lg shadow-indigo-600/30 transition-all font-mono"
                >
                  <span>Inspect Dashboard</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Main Scan Form Selector */}
      <ScanWorkflow onStartScan={handleStartScan} isScanning={isScanning} />

    </div>
  );
}
