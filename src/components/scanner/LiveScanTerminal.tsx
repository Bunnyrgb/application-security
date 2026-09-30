'use client';

import React from 'react';
import { Terminal, Shield, CheckCircle2, Loader2, AlertTriangle, Cpu, Radio } from 'lucide-react';
import { ScanTelemetryStep } from '@/types/security';

interface LiveScanTerminalProps {
  progress: number;
  currentStepMessage: string;
  telemetryLogs: ScanTelemetryStep[];
  isScanning: boolean;
}

export default function LiveScanTerminal({
  progress,
  currentStepMessage,
  telemetryLogs,
  isScanning,
}: LiveScanTerminalProps) {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#080c16] overflow-hidden shadow-2xl relative font-mono">
      {/* Terminal Title Bar */}
      <div className="h-10 bg-[#0c111e] border-b border-slate-800/80 px-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <span className="text-xs text-slate-400 font-mono ml-2 flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyber-cyan" />
            securelens-core-daemon // worker-sandbox-409
          </span>
        </div>

        <div className="flex items-center gap-3">
          {isScanning ? (
            <span className="flex items-center gap-1.5 text-xs text-cyber-cyan">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Scanning Active ({progress}%)
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-xs text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Pipeline Finished
            </span>
          )}
        </div>
      </div>

      {/* Progress Bar Header */}
      <div className="w-full bg-slate-900 h-1.5">
        <div 
          className="bg-gradient-to-r from-indigo-500 via-cyan-400 to-emerald-400 h-1.5 transition-all duration-300"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Terminal Log Output */}
      <div className="p-4 sm:p-6 space-y-3 min-h-[260px] text-xs">
        {telemetryLogs.map((log, index) => (
          <div 
            key={index}
            className="flex items-start gap-3 transition-opacity duration-300 animate-fadeIn"
          >
            <span className="text-slate-500 shrink-0 select-none">
              [{log.timestamp}]
            </span>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="text-slate-200 font-semibold">{log.step}</span>
              </div>
              {log.detail && (
                <p className="text-slate-400 text-[11px] mt-0.5 pl-5">
                  ↳ {log.detail}
                </p>
              )}
            </div>
          </div>
        ))}

        {isScanning && (
          <div className="flex items-center gap-3 pt-2 text-cyber-cyan animate-pulse">
            <span className="text-slate-500">[{new Date().toLocaleTimeString()}]</span>
            <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
            <span>{currentStepMessage || 'Processing security AST heuristics...'}</span>
          </div>
        )}
      </div>

      {/* Terminal Footer */}
      <div className="px-4 py-2 bg-[#090d18] border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
        <span className="flex items-center gap-1">
          <Cpu className="w-3 h-3 text-cyan-400" />
          Container: Isolated (Network Egress Restricted)
        </span>
        <span className="text-slate-400">Rules Engine: v2.4 (412 SAST Signatures)</span>
      </div>
    </div>
  );
}
