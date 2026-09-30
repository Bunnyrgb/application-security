'use client';

import React from 'react';
import { AlertOctagon, Flame, AlertTriangle, ShieldAlert, Info } from 'lucide-react';
import { SeverityLevel } from '@/types/security';

interface SeverityCardsProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  selectedSeverity?: SeverityLevel | 'all';
  onSelectSeverity?: (severity: SeverityLevel | 'all') => void;
}

export default function SeverityCards({
  critical,
  high,
  medium,
  low,
  info,
  selectedSeverity = 'all',
  onSelectSeverity,
}: SeverityCardsProps) {
  const cards = [
    {
      level: 'critical' as SeverityLevel,
      label: 'Critical',
      count: critical,
      range: 'CVSS 9.0 - 10.0',
      icon: AlertOctagon,
      bg: 'bg-rose-950/20 border-rose-800/40 hover:border-rose-600/80',
      activeBorder: 'border-rose-500 shadow-rose-950/50',
      textColor: 'text-rose-400',
      desc: 'Immediate remote compromise',
    },
    {
      level: 'high' as SeverityLevel,
      label: 'High',
      count: high,
      range: 'CVSS 7.0 - 8.9',
      icon: Flame,
      bg: 'bg-orange-950/20 border-orange-800/40 hover:border-orange-600/80',
      activeBorder: 'border-orange-500 shadow-orange-950/50',
      textColor: 'text-orange-400',
      desc: 'Privilege escalation risk',
    },
    {
      level: 'medium' as SeverityLevel,
      label: 'Medium',
      count: medium,
      range: 'CVSS 4.0 - 6.9',
      icon: AlertTriangle,
      bg: 'bg-amber-950/20 border-amber-800/40 hover:border-amber-600/80',
      activeBorder: 'border-amber-500 shadow-amber-950/50',
      textColor: 'text-amber-400',
      desc: 'Conditional bypass or XSS',
    },
    {
      level: 'low' as SeverityLevel,
      label: 'Low',
      count: low,
      range: 'CVSS 0.1 - 3.9',
      icon: ShieldAlert,
      bg: 'bg-blue-950/20 border-blue-800/40 hover:border-blue-600/80',
      activeBorder: 'border-blue-500 shadow-blue-950/50',
      textColor: 'text-blue-400',
      desc: 'Hardening & best practice',
    },
    {
      level: 'informational' as SeverityLevel,
      label: 'Informational',
      count: info,
      range: 'Audit Notes',
      icon: Info,
      bg: 'bg-emerald-950/20 border-emerald-800/40 hover:border-emerald-600/80',
      activeBorder: 'border-emerald-500 shadow-emerald-950/50',
      textColor: 'text-emerald-400',
      desc: 'Security hygiene observations',
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      {cards.map((c) => {
        const Icon = c.icon;
        const isSelected = selectedSeverity === c.level;

        return (
          <button
            key={c.level}
            onClick={() => onSelectSeverity && onSelectSeverity(isSelected ? 'all' : c.level)}
            className={`p-3.5 rounded-xl border text-left transition-all ${c.bg} ${
              isSelected ? `${c.activeBorder} shadow-lg ring-1 ring-cyan-500/50` : ''
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-medium text-slate-300">
                {c.label}
              </span>
              <Icon className={`w-4 h-4 ${c.textColor}`} />
            </div>

            <div className="mt-2 flex items-baseline gap-2">
              <span className={`text-2xl font-mono font-bold ${c.textColor}`}>
                {c.count}
              </span>
              <span className="text-[10px] font-mono text-slate-400">
                findings
              </span>
            </div>

            <div className="mt-1 text-[10px] text-slate-500 font-mono">
              {c.range}
            </div>
          </button>
        );
      })}
    </div>
  );
}
