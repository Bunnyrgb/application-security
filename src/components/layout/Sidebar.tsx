'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  LayoutDashboard, 
  Layers, 
  Radar, 
  History, 
  ShieldAlert, 
  FileText, 
  Boxes, 
  Bot, 
  TrendingUp, 
  Settings, 
  ShieldCheck, 
  ChevronRight,
  Sparkles
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';

export default function Sidebar() {
  const pathname = usePathname();
  const { activeApp, vulnerabilities } = useSecurity();

  const appVulns = activeApp 
    ? vulnerabilities.filter(v => v.application_id === activeApp.id) 
    : vulnerabilities;

  const activeCriticals = appVulns.filter(v => v.severity === 'critical' && v.status === 'confirmed').length;
  const activeHighs = appVulns.filter(v => v.severity === 'high' && v.status === 'confirmed').length;

  const navItems = [
    { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    { label: 'My Applications', href: '/dashboard/apps', icon: Layers },
    { label: 'New Scan', href: '/dashboard/new-scan', icon: Radar, highlight: true },
    { label: 'Scan History', href: '/dashboard/scan-history', icon: History },
    { 
      label: 'Vulnerabilities', 
      href: '/dashboard/vulnerabilities', 
      icon: ShieldAlert,
      badge: activeCriticals > 0 ? `${activeCriticals} Crit` : undefined,
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/40'
    },
    { label: 'Dependencies (SCA)', href: '/dashboard/dependencies', icon: Boxes },
    { label: 'Security Reports', href: '/dashboard/reports', icon: FileText },
    { label: 'Security Progress', href: '/dashboard/progress', icon: TrendingUp },
    { 
      label: 'Security Assistant', 
      href: '/dashboard/assistant', 
      icon: Bot,
      aiBadge: true
    },
    { 
      label: 'Admin Panel', 
      href: '/dashboard/admin', 
      icon: Settings,
      badge: 'ROOT',
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
    },
    { label: 'Alert Settings', href: '/dashboard/settings', icon: Sparkles },
  ];

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-[#090d18] flex flex-col shrink-0 min-h-screen">
      {/* Brand Header */}
      <div className="h-16 px-5 border-b border-slate-800/80 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 via-cyan-500 to-emerald-400 p-[1px]">
            <div className="w-full h-full bg-[#080d1a] rounded-[7px] flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-cyber-cyan" />
            </div>
          </div>
          <span className="font-mono font-bold tracking-tight text-white flex items-center gap-1.5">
            SecureLens
            <span className="text-[10px] px-1 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              v2.4
            </span>
          </span>
        </Link>
      </div>

      {/* Active App Badge */}
      <div className="p-3 mx-3 my-3 rounded-lg bg-[#0e1424] border border-slate-800/80">
        <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1 flex items-center justify-between">
          <span>Active Target</span>
          <span className={activeApp ? "text-emerald-400 flex items-center gap-1 text-[10px]" : "text-amber-400 text-[10px]"}>
            <span className={`w-1.5 h-1.5 rounded-full ${activeApp ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            {activeApp ? 'Live' : 'None'}
          </span>
        </div>
        <div className="text-xs font-semibold text-slate-200 truncate font-mono">
          {activeApp ? activeApp.name : 'No Target Configured'}
        </div>
        <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
          <span>Security Score</span>
          <span className={`font-mono font-bold ${activeApp ? (activeApp.current_score >= 80 ? 'text-emerald-400' : activeApp.current_score >= 60 ? 'text-amber-400' : 'text-rose-400') : 'text-slate-500'}`}>
            {activeApp ? `${activeApp.current_score}/100` : '--/100'}
          </span>
        </div>
      </div>

      {/* Navigation links */}
      <nav className="flex-1 px-3 space-y-1 overflow-y-auto py-2">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all group ${
                isActive
                  ? 'bg-indigo-600/20 text-white border border-indigo-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 transition-colors ${
                  isActive ? 'text-cyber-cyan' : 'text-slate-400 group-hover:text-slate-200'
                }`} />
                <span>{item.label}</span>
              </div>

              <div className="flex items-center gap-1.5">
                {item.aiBadge && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold bg-gradient-to-r from-purple-500/20 to-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-0.5">
                    <Sparkles className="w-2.5 h-2.5 text-cyan-400" />
                    AI
                  </span>
                )}
                {item.badge && (
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
                {item.highlight && !isActive && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                )}
              </div>
            </Link>
          );
        })}
      </nav>

      {/* Bottom User / Quick Action */}
      <div className="p-3 border-t border-slate-800/80 bg-[#070b14]">
        <Link
          href="/dashboard/new-scan"
          className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-indigo-600 to-cyan-600 hover:opacity-90 shadow-md shadow-indigo-600/30 transition-all font-mono"
        >
          <Radar className="w-3.5 h-3.5" />
          <span>Launch Scan</span>
        </Link>
      </div>
    </aside>
  );
}
