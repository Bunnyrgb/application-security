'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Users, 
  Layers, 
  Cpu, 
  Sliders, 
  History, 
  Plus, 
  Trash2, 
  RotateCcw, 
  CheckCircle2, 
  AlertTriangle, 
  Key, 
  Server, 
  ExternalLink,
  Sparkles,
  Radar
} from 'lucide-react';
import { useSecurity, AdminUser } from '@/context/SecurityContext';
import { formatDate } from '@/lib/utils';

export default function AdminPanelPage() {
  const { 
    applications, 
    activeApp, 
    selectApplication, 
    addNewApplication, 
    deleteApplication,
    adminUsers, 
    addAdminUser, 
    updateUserRole, 
    toggleUserStatus, 
    deleteUser,
    auditLogs,
    scannerRules,
    toggleScannerRule,
    clearAllData,
    loadDemoData
  } = useSecurity();

  const [activeTab, setActiveTab] = useState<'apps' | 'users' | 'rules' | 'logs'>('apps');

  // New App Form
  const [showAddApp, setShowAddApp] = useState(false);
  const [appName, setAppName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [appEnv, setAppEnv] = useState<'production' | 'staging' | 'development'>('production');

  // New User Form
  const [showAddUser, setShowAddUser] = useState(false);
  const [userName, setUserName] = useState('');
  const [userEmail, setUserEmail] = useState('');
  const [userRole, setUserRole] = useState<AdminUser['role']>('security_analyst');

  const handleCreateApp = (e: React.FormEvent) => {
    e.preventDefault();
    if (!appName.trim()) return;
    addNewApplication({
      name: appName,
      repository_url: repoUrl || undefined,
      environment: appEnv,
    });
    setAppName('');
    setRepoUrl('');
    setShowAddApp(false);
  };

  const handleCreateUser = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userEmail.trim()) return;
    addAdminUser({
      name: userName || userEmail.split('@')[0],
      email: userEmail,
      role: userRole,
      status: 'active',
    });
    setUserName('');
    setUserEmail('');
    setShowAddUser(false);
  };

  return (
    <div className="space-y-6">
      {/* Admin Panel Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/20 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>ROOT SECURITY ADMINISTRATION</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-sans">
            SecureLens Admin Panel
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage target applications, IAM user permissions, AST scanning rules, and audit logs.
          </p>
        </div>

        {/* Global Workspace Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={() => {
              if (confirm('Are you sure you want to reset all applications and scans to a completely clean slate?')) {
                clearAllData();
              }
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Wipe Clean (0 Apps)</span>
          </button>

          <button
            onClick={loadDemoData}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Load Sample App</span>
          </button>
        </div>
      </div>

      {/* System Status Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="glass-card p-4 rounded-xl space-y-1">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Monitored Apps</div>
          <div className="text-2xl font-bold font-mono text-white">{applications.length}</div>
          <div className="text-[10px] text-cyan-400 font-mono">Target Repositories</div>
        </div>

        <div className="glass-card p-4 rounded-xl space-y-1">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Active Analysts</div>
          <div className="text-2xl font-bold font-mono text-white">{adminUsers.length}</div>
          <div className="text-[10px] text-emerald-400 font-mono">IAM Accounts</div>
        </div>

        <div className="glass-card p-4 rounded-xl space-y-1">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Heuristics Engine</div>
          <div className="text-2xl font-bold font-mono text-cyan-400">v2.4 Core</div>
          <div className="text-[10px] text-slate-400 font-mono">AST Rules Active ({scannerRules.filter(r => r.enabled).length})</div>
        </div>

        <div className="glass-card p-4 rounded-xl space-y-1">
          <div className="text-[11px] font-mono text-slate-400 uppercase">Sandbox Cluster</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">Isolated</div>
          <div className="text-[10px] text-emerald-400 font-mono">0 Egress / Safe Execution</div>
        </div>
      </div>

      {/* Admin Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 text-xs font-mono">
        <button
          onClick={() => setActiveTab('apps')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all ${
            activeTab === 'apps'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Application Targets ({applications.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('users')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all ${
            activeTab === 'users'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>User Access & IAM ({adminUsers.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('rules')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all ${
            activeTab === 'rules'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Sliders className="w-4 h-4" />
          <span>Scanner Rules Engine ({scannerRules.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('logs')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all ${
            activeTab === 'logs'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <History className="w-4 h-4" />
          <span>Audit Stream ({auditLogs.length})</span>
        </button>
      </div>

      {/* 1. Applications Target Management */}
      {activeTab === 'apps' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white font-mono">
              Configured Application Targets
            </h3>
            <button
              onClick={() => setShowAddApp(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 hover:opacity-95 text-white shadow-md shadow-cyan-500/20"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register Application</span>
            </button>
          </div>

          {applications.length > 0 ? (
            <div className="rounded-2xl border border-slate-800 bg-[#080d1e] overflow-hidden shadow-xl">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0b1126] text-slate-400 border-b border-slate-800 uppercase text-[11px]">
                  <tr>
                    <th className="p-4">Application</th>
                    <th className="p-4">Environment</th>
                    <th className="p-4">Current Score</th>
                    <th className="p-4">Findings Breakdown</th>
                    <th className="p-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {applications.map((app) => (
                    <tr key={app.id} className="hover:bg-slate-900/40">
                      <td className="p-4">
                        <span className="font-bold text-white block">{app.name}</span>
                        <span className="text-[10px] text-slate-500">{app.repository_url || 'Manual / Local Archive'}</span>
                      </td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 text-[10px] uppercase font-semibold">
                          {app.environment}
                        </span>
                      </td>
                      <td className="p-4 font-bold text-sm">
                        <span className={app.current_score >= 80 ? 'text-emerald-400' : app.current_score >= 60 ? 'text-amber-400' : 'text-rose-400'}>
                          {app.current_score} / 100
                        </span>
                      </td>
                      <td className="p-4">
                        <span className="text-rose-400 font-bold mr-2">{app.critical_count} Crit</span>
                        <span className="text-orange-400 mr-2">{app.high_count} High</span>
                        <span className="text-amber-400 mr-2">{app.medium_count} Med</span>
                        <span className="text-blue-400">{app.low_count} Low</span>
                      </td>
                      <td className="p-4 text-right space-x-2">
                        <Link
                          href="/dashboard"
                          onClick={() => selectApplication(app.id)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
                        >
                          Select
                        </Link>
                        <Link
                          href="/dashboard/new-scan"
                          onClick={() => selectApplication(app.id)}
                          className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white"
                        >
                          Scan
                        </Link>
                        <button
                          onClick={() => deleteApplication(app.id)}
                          className="p-1 rounded text-slate-500 hover:text-rose-400"
                          title="Delete application"
                        >
                          <Trash2 className="w-3.5 h-3.5 inline" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="glass-card p-12 text-center rounded-2xl space-y-3">
              <Layers className="w-10 h-10 text-cyan-400 mx-auto" />
              <h4 className="text-base font-bold text-white">No Applications Configured</h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                You currently have a fresh slate. Create your first application target to begin scanning your codebase and dependencies.
              </p>
              <button
                onClick={() => setShowAddApp(true)}
                className="mt-2 inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-mono font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 text-white shadow-lg"
              >
                <Plus className="w-4 h-4" />
                <span>Create Your First Application</span>
              </button>
            </div>
          )}
        </div>
      )}

      {/* 2. User & IAM Access */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white font-mono">
              Identity & Access Management (RBAC)
            </h3>
            <button
              onClick={() => setShowAddUser(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 hover:opacity-95 text-white shadow-md shadow-cyan-500/20"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Security Member</span>
            </button>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-[#080d1e] overflow-hidden shadow-xl">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0b1126] text-slate-400 border-b border-slate-800 uppercase text-[11px]">
                <tr>
                  <th className="p-4">Name / Email</th>
                  <th className="p-4">Role Assignment</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Last Active</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {adminUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-slate-900/40">
                    <td className="p-4">
                      <span className="font-bold text-white block">{user.name}</span>
                      <span className="text-[10px] text-slate-500">{user.email}</span>
                    </td>
                    <td className="p-4">
                      <select
                        value={user.role}
                        onChange={(e) => updateUserRole(user.id, e.target.value as AdminUser['role'])}
                        className="bg-[#040816] border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:border-cyan-500"
                      >
                        <option value="admin">Admin (Full Control)</option>
                        <option value="security_analyst">Security Analyst</option>
                        <option value="developer">Developer (Triage Only)</option>
                        <option value="auditor">Auditor (Read-Only)</option>
                      </select>
                    </td>
                    <td className="p-4">
                      <button
                        onClick={() => toggleUserStatus(user.id)}
                        className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold border transition-colors ${
                          user.status === 'active'
                            ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40 hover:bg-emerald-900/60'
                            : 'bg-rose-950/60 text-rose-300 border-rose-800/40 hover:bg-rose-900/60'
                        }`}
                      >
                        {user.status}
                      </button>
                    </td>
                    <td className="p-4 text-slate-400">{user.last_login}</td>
                    <td className="p-4 text-right">
                      {user.role !== 'admin' && (
                        <button
                          onClick={() => deleteUser(user.id)}
                          className="p-1 rounded text-slate-500 hover:text-rose-400"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 3. Scanner Rules Engine */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white font-mono">
                Static Analysis & SAST Heuristic Rules
              </h3>
              <p className="text-xs text-slate-400">
                Enable or disable vulnerability rules according to organizational compliance policy.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {scannerRules.map((rule) => (
              <div 
                key={rule.id}
                className="glass-card p-5 rounded-2xl flex items-start justify-between gap-4"
              >
                <div className="space-y-1.5 flex-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold ${
                      rule.severity === 'critical' ? 'bg-rose-950 text-rose-300 border border-rose-800/40' :
                      rule.severity === 'high' ? 'bg-orange-950 text-orange-300 border border-orange-800/40' :
                      'bg-amber-950 text-amber-300 border border-amber-800/40'
                    }`}>
                      {rule.severity}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      {rule.category}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-white font-sans">{rule.name}</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">{rule.description}</p>
                </div>

                <div className="pt-1">
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => toggleScannerRule(rule.id)}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-500"></div>
                  </label>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. Audit Log Stream */}
      {activeTab === 'logs' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white font-mono">
              Cryptographically Timestamped Audit Stream
            </h3>
            <span className="text-xs text-slate-500 font-mono">
              Immutable activity log
            </span>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-[#080d1e] overflow-hidden shadow-xl">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0b1126] text-slate-400 border-b border-slate-800 uppercase text-[11px]">
                <tr>
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">User</th>
                  <th className="p-4">Action Event</th>
                  <th className="p-4">Target Detail</th>
                  <th className="p-4">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/40">
                    <td className="p-4 text-slate-400">{formatDate(log.timestamp)}</td>
                    <td className="p-4 text-slate-300 font-bold">{log.user_email}</td>
                    <td className="p-4 text-cyan-300 font-semibold">{log.action}</td>
                    <td className="p-4 text-slate-300">{log.target}</td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                        log.severity === 'critical' ? 'text-rose-400 bg-rose-950/60' :
                        log.severity === 'warning' ? 'text-amber-400 bg-amber-950/60' :
                        'text-slate-400 bg-slate-900'
                      }`}>
                        {log.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create Application Modal */}
      {showAddApp && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0b1022] border border-cyan-500/30 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white font-mono">
              Register New Application Target
            </h3>
            <p className="text-xs text-slate-400">
              Set up a target application for security scans and automated vulnerability tracking.
            </p>
            <form onSubmit={handleCreateApp} className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-slate-300 block mb-1">Application Name *</label>
                <input
                  type="text"
                  required
                  value={appName}
                  onChange={(e) => setAppName(e.target.value)}
                  placeholder="e.g., Payment Gateway Service"
                  className="w-full px-3 py-2 bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Target URL / Hostname (Optional)</label>
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://mywebsite.com or https://github.com/my-org/repo"
                  className="w-full px-3 py-2 bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <span className="text-[10px] text-slate-400 mt-1 block">
                  Accepts live website URLs, GitHub/GitLab repositories, or API endpoints.
                </span>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Deployment Environment</label>
                <select
                  value={appEnv}
                  onChange={(e) => setAppEnv(e.target.value as any)}
                  className="w-full px-3 py-2 bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddApp(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 text-white"
                >
                  Create Application
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add User Modal */}
      {showAddUser && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0b1022] border border-cyan-500/30 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white font-mono">
              Grant Security Member Access
            </h3>
            <form onSubmit={handleCreateUser} className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-slate-300 block mb-1">Full Name</label>
                <input
                  type="text"
                  value={userName}
                  onChange={(e) => setUserName(e.target.value)}
                  placeholder="e.g. John Doe"
                  className="w-full px-3 py-2 bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Email Address *</label>
                <input
                  type="email"
                  required
                  value={userEmail}
                  onChange={(e) => setUserEmail(e.target.value)}
                  placeholder="analyst@securelens.local"
                  className="w-full px-3 py-2 bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Role Permission</label>
                <select
                  value={userRole}
                  onChange={(e) => setUserRole(e.target.value as AdminUser['role'])}
                  className="w-full px-3 py-2 bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="security_analyst">Security Analyst</option>
                  <option value="developer">Developer</option>
                  <option value="auditor">Auditor</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddUser(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 text-white"
                >
                  Confirm Member
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
