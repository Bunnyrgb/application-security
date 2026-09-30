'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  CheckCircle2, 
  Sparkles, 
  ExternalLink,
  ChevronDown
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import VulnerabilityCard from '@/components/dashboard/VulnerabilityCard';
import { SeverityLevel, TriageStatus, VulnerabilityCategory } from '@/types/security';

export default function VulnerabilitiesPage() {
  const { vulnerabilities, activeApp } = useSecurity();

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<TriageStatus | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<VulnerabilityCategory | 'all'>('all');

  const categories: VulnerabilityCategory[] = [
    'Authentication',
    'Authorization',
    'Input Security',
    'API Security',
    'Secrets',
    'Cryptography',
    'Configuration',
    'Dependencies'
  ];

  const appVulns = activeApp 
    ? vulnerabilities.filter(v => v.application_id === activeApp.id) 
    : vulnerabilities;

  const filtered = appVulns.filter(v => {
    const matchesSearch = 
      v.title.toLowerCase().includes(search.toLowerCase()) ||
      v.location.toLowerCase().includes(search.toLowerCase()) ||
      v.cwe_id.toLowerCase().includes(search.toLowerCase()) ||
      v.owasp_category.toLowerCase().includes(search.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || v.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || v.status === statusFilter;
    const matchesCategory = categoryFilter === 'all' || v.category === categoryFilter;

    return matchesSearch && matchesSeverity && matchesStatus && matchesCategory;
  });

  const confirmedCount = appVulns.filter(v => v.status === 'confirmed').length;
  const fixedCount = appVulns.filter(v => v.status === 'fixed').length;
  const falsePositiveCount = appVulns.filter(v => v.status === 'false_positive').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>Vulnerability Posture Management</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Vulnerabilities & Security Findings
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Review detailed vulnerability cards, inspect before/after fix diffs, triage false positives, and consult SecureLens AI.
          </p>
        </div>

        {/* Triage Stats Pills */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 rounded-lg bg-rose-950/30 text-rose-300 border border-rose-800/40">
            {confirmedCount} Active
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-emerald-950/30 text-emerald-300 border border-emerald-800/40">
            {fixedCount} Resolved
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-purple-950/30 text-purple-300 border border-purple-800/40">
            {falsePositiveCount} False Positives
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-[#0b101e] border border-slate-800 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by title, CWE, or file..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#070b14] border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as SeverityLevel | 'all')}
            className="px-3 py-1.5 rounded-lg bg-[#070b14] border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical (CVSS 9.0+)</option>
            <option value="high">High (CVSS 7.0 - 8.9)</option>
            <option value="medium">Medium (CVSS 4.0 - 6.9)</option>
            <option value="low">Low (CVSS 0.1 - 3.9)</option>
            <option value="informational">Informational</option>
          </select>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as VulnerabilityCategory | 'all')}
            className="px-3 py-1.5 rounded-lg bg-[#070b14] border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Categories</option>
            {categories.map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as TriageStatus | 'all')}
            className="px-3 py-1.5 rounded-lg bg-[#070b14] border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Triage States</option>
            <option value="confirmed">Confirmed Active</option>
            <option value="fixed">Fixed / Resolved</option>
            <option value="false_positive">False Positive</option>
            <option value="accepted_risk">Accepted Risk</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filtered.length > 0 ? (
          filtered.map(vuln => (
            <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
          ))
        ) : (
          <div className="p-12 text-center rounded-2xl bg-[#0b101e] border border-slate-800 space-y-3">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
            <h3 className="text-sm font-semibold text-white">No Vulnerabilities Found</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              No active findings match the selected filters. Try broadening your filter criteria or executing a new security scan.
            </p>
          </div>
        )}
      </div>

    </div>
  );
}
