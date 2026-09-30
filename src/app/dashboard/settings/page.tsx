'use client';

import React, { useState, useEffect } from 'react';
import { 
  Settings, 
  Users, 
  Bell, 
  Key, 
  Building2,
  User,
  Mail, 
  Plus, 
  Check, 
  Copy,
  Trash2,
  RefreshCw,
  AlertTriangle,
  ShieldCheck,
  Save,
  UserCheck,
  ShieldAlert
} from 'lucide-react';
import { useSecurity, AdminUser } from '@/context/SecurityContext';

export default function SettingsPage() {
  const { 
    userProfile, 
    updateUserProfile,
    adminUsers, 
    addAdminUser, 
    updateUserRole, 
    toggleUserStatus, 
    deleteUser,
    clearAllData
  } = useSecurity();

  const [activeTab, setActiveTab] = useState<'profile' | 'team' | 'notifications' | 'api' | 'danger'>('profile');

  // Organization & Profile Form state
  const [orgName, setOrgName] = useState(userProfile.organization || '');
  const [fullName, setFullName] = useState(userProfile.full_name || '');
  const [email, setEmail] = useState(userProfile.email || '');
  const [profileSaved, setProfileSaved] = useState(false);

  // Sync profile form when userProfile changes
  useEffect(() => {
    setOrgName(userProfile.organization || '');
    setFullName(userProfile.full_name || '');
    setEmail(userProfile.email || '');
  }, [userProfile]);

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    updateUserProfile({
      organization: orgName.trim() || 'Security Operations Center',
      full_name: fullName.trim() || 'System Administrator',
      email: email.trim() || 'admin@securelens.local',
    });
    setProfileSaved(true);
    setTimeout(() => setProfileSaved(false), 2500);
  };

  // Team Invite Form state
  const [inviteName, setInviteName] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<AdminUser['role']>('security_analyst');
  const [inviteSuccess, setInviteSuccess] = useState(false);

  const handleInvite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;

    addAdminUser({
      name: inviteName.trim() || inviteEmail.split('@')[0],
      email: inviteEmail.trim(),
      role: inviteRole,
      status: 'active',
    });

    setInviteName('');
    setInviteEmail('');
    setInviteSuccess(true);
    setTimeout(() => setInviteSuccess(false), 2500);
  };

  // Notification Preferences (persisted in localStorage)
  const [notifyOnScan, setNotifyOnScan] = useState(true);
  const [notifyOnCritical, setNotifyOnCritical] = useState(true);
  const [notifyOnDepCve, setNotifyOnDepCve] = useState(true);
  const [notifyOnScoreDrop, setNotifyOnScoreDrop] = useState(true);
  const [notifyOnRegression, setNotifyOnRegression] = useState(true);
  const [prefsSaved, setPrefsSaved] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem('securelens_alert_prefs');
      if (saved) {
        const p = JSON.parse(saved);
        if (typeof p.notifyOnScan === 'boolean') setNotifyOnScan(p.notifyOnScan);
        if (typeof p.notifyOnCritical === 'boolean') setNotifyOnCritical(p.notifyOnCritical);
        if (typeof p.notifyOnDepCve === 'boolean') setNotifyOnDepCve(p.notifyOnDepCve);
        if (typeof p.notifyOnScoreDrop === 'boolean') setNotifyOnScoreDrop(p.notifyOnScoreDrop);
        if (typeof p.notifyOnRegression === 'boolean') setNotifyOnRegression(p.notifyOnRegression);
      }
    } catch {
      // ignore
    }
  }, []);

  const saveAlertPrefs = (updates: {
    scan?: boolean;
    crit?: boolean;
    dep?: boolean;
    score?: boolean;
    reg?: boolean;
  }) => {
    const prefs = {
      notifyOnScan: updates.scan !== undefined ? updates.scan : notifyOnScan,
      notifyOnCritical: updates.crit !== undefined ? updates.crit : notifyOnCritical,
      notifyOnDepCve: updates.dep !== undefined ? updates.dep : notifyOnDepCve,
      notifyOnScoreDrop: updates.score !== undefined ? updates.score : notifyOnScoreDrop,
      notifyOnRegression: updates.reg !== undefined ? updates.reg : notifyOnRegression,
    };
    try {
      localStorage.setItem('securelens_alert_prefs', JSON.stringify(prefs));
      setPrefsSaved(true);
      setTimeout(() => setPrefsSaved(false), 1500);
    } catch {
      // ignore
    }
  };

  // API Token State (persisted in localStorage)
  const [apiToken, setApiToken] = useState('sl_live_89f02c918bb3948e918a992bc018');
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedWorkflow, setCopiedWorkflow] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem('securelens_api_token');
      if (saved) setApiToken(saved);
    } catch {
      // ignore
    }
  }, []);

  const regenerateToken = () => {
    const newToken = `sl_live_${Math.random().toString(36).substring(2, 14)}${Math.random().toString(36).substring(2, 14)}`;
    setApiToken(newToken);
    try {
      localStorage.setItem('securelens_api_token', newToken);
    } catch {
      // ignore
    }
  };

  const copyToken = () => {
    navigator.clipboard.writeText(apiToken);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const workflowExample = `name: SecureLens Automated SAST Audit
on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Execute SecureLens Scanner
        uses: securelens/security-action@v2
        with:
          api-token: \${{ secrets.SECURELENS_API_TOKEN }}
          fail-on-severity: 'critical'
          max-score-penalty: 25`;

  const copyWorkflow = () => {
    navigator.clipboard.writeText(workflowExample);
    setCopiedWorkflow(true);
    setTimeout(() => setCopiedWorkflow(false), 2000);
  };

  // Confirmation state for clearing workspace
  const [confirmReset, setConfirmReset] = useState(false);

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Header */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
          <Settings className="w-4 h-4" />
          <span>Organization Governance & Configuration</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Settings & Collaboration
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Configure organization profile, team members, automated alert triggers, and headless CI/CD scanning tokens.
        </p>
      </div>

      {/* Settings Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 text-xs font-mono overflow-x-auto pb-1">
        <button
          onClick={() => setActiveTab('profile')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all shrink-0 ${
            activeTab === 'profile'
              ? 'border-cyan-400 text-cyber-cyan bg-cyan-500/5'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Building2 className="w-4 h-4" />
          <span>Organization Profile</span>
        </button>

        <button
          onClick={() => setActiveTab('team')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all shrink-0 ${
            activeTab === 'team'
              ? 'border-cyan-400 text-cyber-cyan bg-cyan-500/5'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>Team Collaboration ({adminUsers.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('notifications')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all shrink-0 ${
            activeTab === 'notifications'
              ? 'border-cyan-400 text-cyber-cyan bg-cyan-500/5'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Bell className="w-4 h-4" />
          <span>Alert Rules</span>
        </button>

        <button
          onClick={() => setActiveTab('api')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all shrink-0 ${
            activeTab === 'api'
              ? 'border-cyan-400 text-cyber-cyan bg-cyan-500/5'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Key className="w-4 h-4" />
          <span>API Tokens & CI/CD</span>
        </button>

        <button
          onClick={() => setActiveTab('danger')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-semibold transition-all shrink-0 ${
            activeTab === 'danger'
              ? 'border-rose-400 text-rose-400 bg-rose-500/5'
              : 'border-transparent text-slate-400 hover:text-rose-300'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Reset Workspace</span>
        </button>
      </div>

      {/* 1. Profile / Organization Tab */}
      {activeTab === 'profile' && (
        <div className="space-y-6">
          <form onSubmit={handleSaveProfile} className="p-6 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div>
                <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-cyber-cyan" />
                  <span>Workspace Organization Details</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Update your enterprise identity, administrator contact, and report branding.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-xs font-mono uppercase">
                {userProfile.user_type} Tier
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="space-y-1.5">
                <label className="text-slate-300 font-bold block">
                  Organization / Company Name
                </label>
                <input
                  type="text"
                  required
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="e.g. My Security Lab or TechCorp"
                  className="w-full px-3.5 py-2.5 bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-300 font-bold block">
                  Administrator Full Name
                </label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. System Administrator"
                  className="w-full px-3.5 py-2.5 bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-300 font-bold block">
                  Administrator Contact Email
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@yourdomain.com"
                  className="w-full px-3.5 py-2.5 bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-300 font-bold block">
                  Active Access Role
                </label>
                <input
                  type="text"
                  disabled
                  value={`${userProfile.role.toUpperCase()} (Primary Administrator)`}
                  className="w-full px-3.5 py-2.5 bg-[#070b14]/50 border border-slate-800/60 rounded-lg text-slate-400 cursor-not-allowed"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-800/80">
              <span className="text-[11px] text-slate-400 font-mono">
                Changes persist automatically into local storage and reflect in executive reports.
              </span>

              <button
                type="submit"
                className="px-5 py-2 rounded-xl text-xs font-mono font-semibold bg-gradient-to-r from-indigo-600 via-cyan-600 to-indigo-600 hover:opacity-95 text-white flex items-center gap-2 shadow-md shadow-indigo-600/30 transition-all"
              >
                {profileSaved ? (
                  <>
                    <Check className="w-4 h-4 text-emerald-300" />
                    <span>Saved Successfully</span>
                  </>
                ) : (
                  <>
                    <Save className="w-4 h-4" />
                    <span>Save Profile Changes</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* 2. Team Collaboration Tab */}
      {activeTab === 'team' && (
        <div className="space-y-6">
          {/* Invite Form */}
          <form onSubmit={handleInvite} className="p-5 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Users className="w-4 h-4 text-cyber-cyan" />
                <span>Add Team Member / Security Analyst</span>
              </h3>
              {inviteSuccess && (
                <span className="text-emerald-400 text-xs font-mono flex items-center gap-1">
                  <Check className="w-3.5 h-3.5" /> Member added to workspace
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
              <input
                type="text"
                value={inviteName}
                onChange={(e) => setInviteName(e.target.value)}
                placeholder="Full Name (optional)"
                className="px-3 py-2 text-xs font-mono bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <input
                type="email"
                required
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="colleague@organization.com"
                className="px-3 py-2 text-xs font-mono bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <select
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value as AdminUser['role'])}
                className="px-3 py-2 text-xs font-mono bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="security_analyst">Security Analyst</option>
                <option value="developer">Developer</option>
                <option value="auditor">Auditor</option>
                <option value="admin">Administrator</option>
              </select>
              <button
                type="submit"
                className="px-4 py-2 rounded-lg text-xs font-mono font-semibold bg-gradient-to-r from-indigo-600 to-cyan-600 hover:opacity-90 text-white flex items-center justify-center gap-1.5 shadow-md shadow-indigo-600/30 transition-all"
              >
                <Plus className="w-4 h-4" />
                <span>Add Member</span>
              </button>
            </div>
          </form>

          {/* Members Table */}
          <div className="rounded-2xl border border-slate-800 bg-[#0b101e] overflow-hidden shadow-xl">
            <div className="px-5 py-3 border-b border-slate-800 flex items-center justify-between bg-[#0c111e]">
              <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                Active Organization Collaborators
              </span>
              <span className="text-[11px] font-mono text-cyan-400">
                {adminUsers.length} Authorized Users
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#080c16] text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="p-4">User</th>
                    <th className="p-4">Role</th>
                    <th className="p-4">Status</th>
                    <th className="p-4">Last Activity</th>
                    <th className="p-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {adminUsers.map((member) => (
                    <tr key={member.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-cyan-400 uppercase shrink-0">
                            {member.name ? member.name.slice(0, 2) : member.email.slice(0, 2)}
                          </div>
                          <div>
                            <div className="font-bold text-white">{member.name || member.email.split('@')[0]}</div>
                            <div className="text-[11px] text-slate-400">{member.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="p-4">
                        <select
                          value={member.role}
                          onChange={(e) => updateUserRole(member.id, e.target.value as AdminUser['role'])}
                          className="px-2.5 py-1 bg-[#070b14] border border-slate-800 rounded text-[11px] font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                        >
                          <option value="admin">Administrator</option>
                          <option value="security_analyst">Security Analyst</option>
                          <option value="developer">Developer</option>
                          <option value="auditor">Auditor</option>
                        </select>
                      </td>
                      <td className="p-4">
                        <button
                          onClick={() => toggleUserStatus(member.id)}
                          title="Click to toggle status"
                          className={`text-[11px] px-2 py-0.5 rounded border transition-colors ${
                            member.status === 'active'
                              ? 'bg-emerald-950/50 text-emerald-400 border-emerald-800/40 hover:bg-emerald-900/50'
                              : 'bg-rose-950/50 text-rose-400 border-rose-800/40 hover:bg-rose-900/50'
                          }`}
                        >
                          ● {member.status.toUpperCase()}
                        </button>
                      </td>
                      <td className="p-4 text-slate-400 text-[11px]">
                        {member.last_login}
                      </td>
                      <td className="p-4 text-right">
                        {member.email !== userProfile.email && (
                          <button
                            onClick={() => deleteUser(member.id)}
                            title="Remove collaborator"
                            className="text-slate-500 hover:text-rose-400 p-1.5 rounded transition-colors hover:bg-rose-500/10"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 3. Notifications Tab */}
      {activeTab === 'notifications' && (
        <div className="p-6 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div>
              <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
                <Bell className="w-4 h-4 text-cyber-cyan" />
                <span>Automated Alert Rules & Dispatch Preferences</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Control which security events trigger automated warnings in the console and notifications feed.
              </p>
            </div>
            {prefsSaved && (
              <span className="text-emerald-400 text-xs font-mono flex items-center gap-1">
                <Check className="w-3.5 h-3.5" /> Preferences Saved
              </span>
            )}
          </div>

          <div className="space-y-4 text-xs font-mono divide-y divide-slate-800/80">
            <div className="flex items-center justify-between pt-3">
              <div>
                <span className="text-white block font-semibold">Scan Finalization</span>
                <span className="text-slate-400 text-[11px]">Notify when an automated pipeline run or URL audit completes.</span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnScan}
                onChange={(e) => {
                  setNotifyOnScan(e.target.checked);
                  saveAlertPrefs({ scan: e.target.checked });
                }}
                className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between pt-3">
              <div>
                <span className="text-rose-400 block font-semibold">Critical Threat Discovery</span>
                <span className="text-slate-400 text-[11px]">Dispatch urgent high-priority alerts on CVSS 9.0+ findings (SQLi, Secret leaks).</span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnCritical}
                onChange={(e) => {
                  setNotifyOnCritical(e.target.checked);
                  saveAlertPrefs({ crit: e.target.checked });
                }}
                className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between pt-3">
              <div>
                <span className="text-white block font-semibold">Dependency Advisory (CVE)</span>
                <span className="text-slate-400 text-[11px]">Alert when a third-party package has an active CVE advisory.</span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnDepCve}
                onChange={(e) => {
                  setNotifyOnDepCve(e.target.checked);
                  saveAlertPrefs({ dep: e.target.checked });
                }}
                className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between pt-3">
              <div>
                <span className="text-amber-400 block font-semibold">Security Score Degradation</span>
                <span className="text-slate-400 text-[11px]">Alert when an application score drops below safe threshold (below 80).</span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnScoreDrop}
                onChange={(e) => {
                  setNotifyOnScoreDrop(e.target.checked);
                  saveAlertPrefs({ score: e.target.checked });
                }}
                className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
              />
            </div>

            <div className="flex items-center justify-between pt-3">
              <div>
                <span className="text-purple-400 block font-semibold">Vulnerability Regression</span>
                <span className="text-slate-400 text-[11px]">Trigger immediate warning if a previously fixed defect reappears in a rescan.</span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnRegression}
                onChange={(e) => {
                  setNotifyOnRegression(e.target.checked);
                  saveAlertPrefs({ reg: e.target.checked });
                }}
                className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
              />
            </div>
          </div>
        </div>
      )}

      {/* 4. API & CI/CD Tab */}
      {activeTab === 'api' && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
                <Key className="w-4 h-4 text-cyber-cyan" />
                <span>CI/CD Pipeline Security Token</span>
              </h3>
              <button
                onClick={regenerateToken}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Regenerate Key</span>
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Use this secret token in GitHub Actions, GitLab CI, or Jenkins to trigger automated security audits on pull requests.
            </p>

            <div className="flex items-center gap-2">
              <input
                type="text"
                readOnly
                value={apiToken}
                className="flex-1 px-4 py-2.5 text-xs font-mono bg-[#070b14] border border-slate-800 rounded-lg text-slate-200 select-all"
              />
              <button
                onClick={copyToken}
                className="px-4 py-2.5 rounded-lg text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 transition-colors"
              >
                {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedToken ? 'Copied' : 'Copy Token'}</span>
              </button>
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-[#0b101e] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
                GitHub Actions Workflow Example (.github/workflows/security.yml)
              </h4>
              <button
                onClick={copyWorkflow}
                className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1"
              >
                {copiedWorkflow ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedWorkflow ? 'Copied Workflow' : 'Copy Workflow YAML'}</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-[#060912] border border-slate-800 text-xs font-mono text-cyan-200 overflow-x-auto leading-relaxed">
              <code>{workflowExample}</code>
            </pre>
          </div>
        </div>
      )}

      {/* 5. Danger Zone / Reset Workspace */}
      {activeTab === 'danger' && (
        <div className="p-6 rounded-2xl bg-[#14080c] border border-rose-900/60 space-y-4">
          <div className="flex items-center gap-2 text-rose-400 font-mono font-bold text-sm">
            <ShieldAlert className="w-5 h-5" />
            <span>Workspace Reset & Data Purge</span>
          </div>

          <p className="text-xs text-rose-200/80 leading-relaxed font-mono">
            This will wipe all registered target applications, historical vulnerability findings, dependency analyses, and scan logs. This gives you a completely clean, fresh dashboard state.
          </p>

          {!confirmReset ? (
            <button
              onClick={() => setConfirmReset(true)}
              className="px-5 py-2.5 rounded-xl text-xs font-mono font-semibold bg-rose-600 hover:bg-rose-700 text-white flex items-center gap-2 transition-colors shadow-lg shadow-rose-900/30"
            >
              <Trash2 className="w-4 h-4" />
              <span>Wipe Workspace & Start 100% Fresh</span>
            </button>
          ) : (
            <div className="p-4 rounded-xl bg-rose-950/70 border border-rose-700/50 space-y-3">
              <p className="text-xs text-rose-300 font-bold font-mono">
                ⚠️ Are you completely sure? This will delete all applications and scans from your browser.
              </p>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    clearAllData();
                    setConfirmReset(false);
                  }}
                  className="px-4 py-2 rounded-lg text-xs font-mono font-bold bg-rose-600 hover:bg-rose-500 text-white transition-colors"
                >
                  Confirm: Purge All Scan Data
                </button>
                <button
                  onClick={() => setConfirmReset(false)}
                  className="px-4 py-2 rounded-lg text-xs font-mono text-slate-300 hover:text-white border border-slate-700 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
