'use client';

import React from 'react';
import { Shield, ArrowUpRight, TrendingUp } from 'lucide-react';
import { getScoreGrade } from '@/lib/utils';
import { ScoreBreakdown } from '@/types/security';

interface SecurityScoreGaugeProps {
  score: number;
  previousScore?: number;
  breakdown?: ScoreBreakdown;
  size?: 'sm' | 'md' | 'lg';
}

export default function SecurityScoreGauge({
  score,
  previousScore,
  breakdown,
  size = 'md',
}: SecurityScoreGaugeProps) {
  const grade = getScoreGrade(score);
  const scoreDiff = previousScore !== undefined ? score - previousScore : 0;

  // SVG circular progress calculation
  const radius = size === 'lg' ? 64 : size === 'sm' ? 36 : 50;
  const strokeWidth = size === 'lg' ? 10 : size === 'sm' ? 6 : 8;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col sm:flex-row items-center gap-6">
      {/* Circle Gauge */}
      <div className="relative flex items-center justify-center shrink-0">
        <svg 
          className="transform -rotate-90"
          width={(radius + strokeWidth) * 2} 
          height={(radius + strokeWidth) * 2}
        >
          {/* Background Track */}
          <circle
            cx={radius + strokeWidth}
            cy={radius + strokeWidth}
            r={radius}
            stroke="#131b2e"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Progress Ring */}
          <circle
            cx={radius + strokeWidth}
            cy={radius + strokeWidth}
            r={radius}
            stroke={grade.ringColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-extrabold tracking-tight font-mono text-white">
            {score}
          </span>
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
            / 100
          </span>
        </div>
      </div>

      {/* Details & Grade */}
      <div className="space-y-2 text-center sm:text-left flex-1">
        <div className="flex items-center justify-center sm:justify-start gap-2">
          <span className={`text-base font-bold ${grade.color}`}>
            {grade.label}
          </span>
          {scoreDiff !== 0 && (
            <span className={`inline-flex items-center text-xs font-mono px-2 py-0.5 rounded-full ${
              scoreDiff > 0 
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' 
                : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
            }`}>
              <TrendingUp className="w-3 h-3 mr-0.5" />
              {scoreDiff > 0 ? `+${scoreDiff}` : scoreDiff} pts
            </span>
          )}
        </div>
        <p className="text-xs text-slate-400 max-w-sm">
          Calculated dynamically across static code analysis, third-party dependency vulnerabilities, API exposure, and credentials risk.
        </p>

        {/* Category mini breakdown bars */}
        {breakdown && (
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2">
            <div className="p-1.5 rounded bg-[#090d18] border border-slate-800/80">
              <div className="text-[10px] text-slate-400 font-mono">Authentication</div>
              <div className="text-xs font-bold text-slate-200 font-mono">{breakdown.authentication}%</div>
            </div>
            <div className="p-1.5 rounded bg-[#090d18] border border-slate-800/80">
              <div className="text-[10px] text-slate-400 font-mono">Authorization</div>
              <div className="text-xs font-bold text-slate-200 font-mono">{breakdown.authorization}%</div>
            </div>
            <div className="p-1.5 rounded bg-[#090d18] border border-slate-800/80">
              <div className="text-[10px] text-slate-400 font-mono">API Security</div>
              <div className="text-xs font-bold text-slate-200 font-mono">{breakdown.api_security}%</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
