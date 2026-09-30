'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  Search, 
  Bell, 
  ChevronDown, 
  ShieldCheck, 
  Sparkles, 
  Wand2, 
  RefreshCw,
  Sliders,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';

export default function DashboardHeader() {
  const { 
    applications, 
    activeApp, 
    selectApplication, 
    userProfile, 
    fixAllIssues, 
    clearAllData,
    vulnerabilities 
  } = useSecurity();

  const [showAppDropdown, setShowAppDropdown] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const appVulns = activeApp 
    ? vulnerabilities.filter(v => v.application_id === activeApp.id) 
    : vulnerabilities;
  const criticalCount = appVulns.filter(v => v.severity === 'critical' && v.status === 'confirmed').length;

  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#070a12]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      
      {/* Left: App Switcher & Search */}
      <div className="flex items-center gap-4">
        {/* App Switcher Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowAppDropdown(!showAppDropdown)}
            className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-[#0e1424] border border-slate-800 hover:border-slate-700 text-xs font-medium text-slate-200 transition-colors"
          >
            <span className={`w-2 h-2 rounded-full ${activeApp ? 'bg-cyan-400' : 'bg-amber-400'}`} />
            <span className="font-mono max-w-[180px] truncate">{activeApp ? activeApp.name : 'No App Selected'}</span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {showAppDropdown && (
            <div className="absolute left-0 mt-2 w-64 rounded-xl bg-[#0c101c] border border-slate-800 shadow-2xl py-2 z-50">
              <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-400 border-b border-slate-800/80 flex items-center justify-between">
                <span>Switch Target Application</span>
                <Link href="/dashboard/admin" className="text-cyan-400 hover:underline">
                  + Add
                </Link>
              </div>
              {applications.length > 0 ? (
                applications.map(app => (
                  <button
                    key={app.id}
                    onClick={() => {
                      selectApplication(app.id);
                      setShowAppDropdown(false);
                    }}
                    className={`w-full px-3 py-2 text-left text-xs flex items-center justify-between hover:bg-slate-800/60 transition-colors ${
                      app.id === activeApp?.id ? 'text-cyber-cyan bg-cyan-500/10' : 'text-slate-300'
                    }`}
                  >
                    <span className="truncate font-mono">{app.name}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      {app.current_score}/100
                    </span>
                  </button>
                ))
              ) : (
                <div className="px-3 py-3 text-xs text-slate-400 font-mono text-center">
                  No applications yet.
                  <Link href="/dashboard/admin" className="block text-cyan-400 hover:underline mt-1">
                    Create in Admin Panel →
                  </Link>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Global Search bar */}
        <div className="relative hidden md:block">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search vulnerabilities, CVEs, endpoints..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-64 pl-8 pr-3 py-1.5 rounded-lg bg-[#0a0e1a] border border-slate-800/80 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 transition-colors font-mono"
          />
        </div>
      </div>

      {/* Right: Admin Panel quick link, Notifications & Profile */}
      <div className="flex items-center gap-3">
        <Link
          href="/dashboard/admin"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 transition-colors font-mono"
        >
          <Sliders className="w-3.5 h-3.5 text-cyan-400" />
          <span>Admin Panel</span>
        </Link>

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors"
          >
            <Bell className="w-4 h-4" />
            {criticalCount > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 rounded-xl bg-[#0c101c] border border-slate-800 shadow-2xl p-3 z-50 space-y-2">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-xs font-bold text-slate-200">Security Notifications</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono">
                  {criticalCount} Critical
                </span>
              </div>
              <div className="space-y-2 text-xs max-h-60 overflow-y-auto">
                {appVulns.filter(v => v.status === 'confirmed').slice(0, 4).length > 0 ? (
                  appVulns
                    .filter(v => v.status === 'confirmed')
                    .slice(0, 4)
                    .map((vuln) => (
                      <div 
                        key={vuln.id} 
                        className={`p-2 rounded border ${
                          vuln.severity === 'critical'
                            ? 'bg-rose-950/30 border-rose-800/40 text-rose-200'
                            : vuln.severity === 'high'
                            ? 'bg-orange-950/30 border-orange-800/40 text-orange-200'
                            : 'bg-amber-950/30 border-amber-800/40 text-amber-200'
                        }`}
                      >
                        <div className="font-semibold flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                          <span className="truncate">{vuln.title}</span>
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1 truncate">
                          {vuln.location} • CVSS {vuln.cvss_score}
                        </div>
                      </div>
                    ))
                ) : (
                  <div className="p-3 text-center text-slate-400 font-mono text-[11px]">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto mb-1" />
                    All systems normal. 0 active alerts.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Profile */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-xs font-bold text-white uppercase font-mono shadow-sm">
            {userProfile.full_name.slice(0, 2)}
          </div>
          <div className="hidden lg:flex flex-col text-left">
            <span className="text-xs font-medium text-slate-200 leading-none">{userProfile.full_name}</span>
            <span className="text-[10px] text-slate-400 capitalize mt-0.5">{userProfile.role.replace('_', ' ')}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
