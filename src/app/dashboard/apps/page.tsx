'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  Layers, 
  Plus, 
  Radar, 
  ShieldCheck, 
  GitBranch, 
  ExternalLink, 
  Calendar, 
  ChevronRight,
  Sparkles,
  AlertTriangle
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import { formatDate } from '@/lib/utils';

export default function ApplicationsPage() {
  const { applications, activeApp, selectApplication, addNewApplication } = useSecurity();
  const [showAddModal, setShowAddModal] = useState(false);
  const [newAppName, setNewAppName] = useState('');
  const [newRepoUrl, setNewRepoUrl] = useState('');
  const [newEnv, setNewEnv] = useState<'production' | 'staging' | 'development'>('production');

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAppName.trim()) return;
    addNewApplication({
      name: newAppName,
      repository_url: newRepoUrl || undefined,
      environment: newEnv,
    });
    setNewAppName('');
    setNewRepoUrl('');
    setShowAddModal(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
            <Layers className="w-4 h-4" />
            <span>Monitored Assets & Targets</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            My Applications
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage monitored microservices, web applications, and repositories under active vulnerability posture surveillance.
          </p>
        </div>

        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-indigo-600 via-cyan-600 to-indigo-600 hover:opacity-90 shadow-md shadow-indigo-600/30 transition-all font-mono self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Add Application</span>
        </button>
      </div>

      {/* Applications Grid or Empty State */}
      {applications.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {applications.map((app) => {
            const isSelected = activeApp ? app.id === activeApp.id : false;
            const scoreColor =
              app.current_score >= 80 ? 'text-emerald-400' :
              app.current_score >= 60 ? 'text-amber-400' : 'text-rose-400';

            return (
              <div
                key={app.id}
              className={`p-6 rounded-2xl border transition-all flex flex-col justify-between space-y-4 ${
                isSelected
                  ? 'bg-gradient-to-b from-[#0f1730] to-[#0a1020] border-cyan-500/60 shadow-xl shadow-cyan-500/10 ring-1 ring-cyan-500/40'
                  : 'bg-[#0b101e] border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 uppercase">
                    {app.environment}
                  </span>
                  {isSelected && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold">
                      Current Target
                    </span>
                  )}
                </div>

                <div>
                  <h3 className="text-base font-bold text-white font-mono">{app.name}</h3>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2">{app.description}</p>
                </div>

                {app.repository_url && (
                  <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono truncate">
                    <GitBranch className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span className="truncate">{app.repository_url}</span>
                  </div>
                )}

                {/* Score and Findings */}
                <div className="p-3 rounded-xl bg-[#070b14] border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-[10px] font-mono text-slate-400 uppercase">Security Score</div>
                    <div className={`text-2xl font-bold font-mono ${scoreColor}`}>
                      {app.current_score} <span className="text-xs text-slate-500">/ 100</span>
                    </div>
                  </div>

                  <div className="text-right text-[11px] font-mono space-y-0.5">
                    <div className="text-rose-400 font-bold">{app.critical_count} Critical</div>
                    <div className="text-orange-400">{app.high_count} High</div>
                    <div className="text-amber-400">{app.medium_count} Medium</div>
                    <div className="text-blue-400">{app.low_count} Low</div>
                  </div>
                </div>

                <div className="text-[11px] text-slate-500 font-mono">
                  Last Scanned: {formatDate(app.last_scanned_at)}
                </div>
              </div>

              {/* Actions */}
              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80">
                <Link
                  href="/dashboard"
                  onClick={() => selectApplication(app.id)}
                  className="py-2 px-3 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors text-center"
                >
                  View Security
                </Link>
                <Link
                  href="/dashboard/new-scan"
                  onClick={() => selectApplication(app.id)}
                  className="py-2 px-3 rounded-lg text-xs font-mono font-semibold bg-gradient-to-r from-indigo-600 to-cyan-600 text-white hover:opacity-90 transition-opacity text-center flex items-center justify-center gap-1"
                >
                  <Radar className="w-3.5 h-3.5" />
                  <span>Scan Again</span>
                </Link>
              </div>
            </div>
          );
        })}
      </div>
    ) : (
      <div className="p-12 rounded-2xl bg-[#0b101e] border border-slate-800 text-center space-y-4 font-mono">
        <Layers className="w-12 h-12 text-cyan-400 mx-auto" />
        <h3 className="text-sm font-semibold text-white">No Application Targets Registered</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Start auditing your websites, microservices, or codebases by registering a target or running a direct security scan.
        </p>
        <div className="flex items-center justify-center gap-3 pt-2">
          <button
            onClick={() => setShowAddModal(true)}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 text-white"
          >
            + Register Application
          </button>
          <Link
            href="/dashboard/new-scan"
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#121932] border border-slate-700 text-slate-200 hover:text-white"
          >
            Launch Security Scan →
          </Link>
        </div>
      </div>
    )}

      {/* Add App Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0e1424] border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-white font-mono">
              Register New Application Target
            </h3>
            <form onSubmit={handleCreate} className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-slate-400 block mb-1">Application Name *</label>
                <input
                  type="text"
                  required
                  value={newAppName}
                  onChange={(e) => setNewAppName(e.target.value)}
                  placeholder="e.g., Payment Gateway Microservice"
                  className="w-full px-3 py-2 bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Git Repository URL</label>
                <input
                  type="text"
                  value={newRepoUrl}
                  onChange={(e) => setNewRepoUrl(e.target.value)}
                  placeholder="https://github.com/organization/repo"
                  className="w-full px-3 py-2 bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Environment</label>
                <select
                  value={newEnv}
                  onChange={(e) => setNewEnv(e.target.value as any)}
                  className="w-full px-3 py-2 bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg font-semibold bg-cyan-600 hover:bg-cyan-500 text-white"
                >
                  Create Application
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
