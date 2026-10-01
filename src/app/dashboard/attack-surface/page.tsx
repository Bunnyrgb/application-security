'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { 
  Radar, 
  Globe, 
  ExternalLink, 
  Search, 
  Filter, 
  FileText, 
  Lock, 
  Unlock, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Layers,
  ArrowRight,
  Code2
} from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';
import { DiscoveredEndpoint, DiscoveredResource } from '@/types/security';

export default function AttackSurfacePage() {
  const { activeScan, activeApp } = useSecurity();
  const [methodFilter, setMethodFilter] = useState<string>('all');
  const [authFilter, setAuthFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');

  const endpoints: DiscoveredEndpoint[] = activeScan?.discovered_endpoints || [];
  const resources: DiscoveredResource[] = activeScan?.discovered_resources || [];

  const filteredEndpoints = endpoints.filter(ep => {
    const matchesMethod = methodFilter === 'all' || ep.method === methodFilter;
    const matchesAuth = authFilter === 'all' || ep.authRequired === authFilter;
    const matchesSearch = ep.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ep.url.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesMethod && matchesAuth && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <Radar className="w-4 h-4" />
            <span>Perimeter Reconnaissance & Asset Inventory</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Accessible Attack Surface
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Discovered accessible URLs, API endpoints, parameters, authentication boundaries, and public assets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href="/dashboard/new-scan"
            className="px-4 py-2 rounded-xl text-xs font-mono font-semibold bg-gradient-to-r from-cyan-500 to-indigo-600 text-white hover:opacity-95 shadow-lg shadow-cyan-500/20 flex items-center gap-2"
          >
            <Radar className="w-4 h-4" />
            <span>Discover Surface</span>
          </Link>
        </div>
      </div>

      {/* Surface Discovery Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-[11px] font-mono uppercase text-slate-400">Total Surface Endpoints</span>
          <div className="text-2xl font-bold font-mono text-white">
            {endpoints.length > 0 ? endpoints.length : 1}
          </div>
          <span className="text-[10px] font-mono text-cyan-400">Indexed via HTTP crawl & AST</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-[11px] font-mono uppercase text-slate-400">Auth-Gated Endpoints</span>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {endpoints.filter(e => e.authRequired === 'Required').length}
          </div>
          <span className="text-[10px] font-mono text-slate-400">Require session token/login</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-[11px] font-mono uppercase text-slate-400">Public Recon Resources</span>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {resources.length}
          </div>
          <span className="text-[10px] font-mono text-slate-400">robots.txt, security.txt, sitemaps</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0b101e] border border-slate-800 space-y-1">
          <span className="text-[11px] font-mono uppercase text-slate-400">Parameter Surfaces</span>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {endpoints.reduce((acc, curr) => acc + (curr.parameters?.length || 0), 0)}
          </div>
          <span className="text-[10px] font-mono text-slate-400">Input query & path parameters</span>
        </div>
      </div>

      {/* Public Metadata Resources (Section 17) */}
      {resources.length > 0 && (
        <div className="p-5 rounded-xl bg-[#0c1222] border border-slate-800 space-y-3">
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Public Metadata & Policy Resources (RFC 9116 / Robots)</span>
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {resources.map((res, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-[#070b14] border border-slate-800 text-xs font-mono space-y-1">
                <div className="flex items-center justify-between text-cyan-400 font-bold">
                  <span>{res.path}</span>
                  <span className="text-[10px] text-emerald-400">HTTP {res.status}</span>
                </div>
                <p className="text-slate-400 text-[11px]">{res.details}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Discovered Endpoints Table */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            <span>Discovered Endpoints ({filteredEndpoints.length})</span>
          </h2>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search endpoints..."
                className="pl-8 pr-3 py-1.5 rounded-lg text-xs font-mono bg-[#090d18] border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-400 w-44"
              />
            </div>

            {/* Method filter */}
            <select
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
              className="text-xs font-mono bg-[#090d18] border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="all">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>

            {/* Auth filter */}
            <select
              value={authFilter}
              onChange={(e) => setAuthFilter(e.target.value)}
              className="text-xs font-mono bg-[#090d18] border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="all">All Auth States</option>
              <option value="Required">Auth Required</option>
              <option value="Public / None">Public / None</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="rounded-xl border border-slate-800 overflow-hidden bg-[#090d18]">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0e1424] text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
                <tr>
                  <th className="p-3.5 font-semibold">Method</th>
                  <th className="p-3.5 font-semibold">Endpoint Path</th>
                  <th className="p-3.5 font-semibold">Auth State</th>
                  <th className="p-3.5 font-semibold">Parameters</th>
                  <th className="p-3.5 font-semibold">Discovery Source</th>
                  <th className="p-3.5 font-semibold">Risk Indicator</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {filteredEndpoints.map((ep, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        ep.method === 'POST'
                          ? 'bg-indigo-950/60 text-indigo-300 border border-indigo-800/50'
                          : ep.method === 'PUT' || ep.method === 'DELETE'
                          ? 'bg-amber-950/60 text-amber-300 border border-amber-800/50'
                          : 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/50'
                      }`}>
                        {ep.method}
                      </span>
                    </td>
                    <td className="p-3.5 font-semibold text-white truncate max-w-xs">
                      {ep.path}
                    </td>
                    <td className="p-3.5">
                      <span className={`inline-flex items-center gap-1 text-[11px] ${
                        ep.authRequired === 'Required' ? 'text-purple-300' : 'text-slate-400'
                      }`}>
                        {ep.authRequired === 'Required' ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                        <span>{ep.authRequired}</span>
                      </span>
                    </td>
                    <td className="p-3.5 text-slate-400">
                      {ep.parameters && ep.parameters.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {ep.parameters.map((p, pIdx) => (
                            <span key={pIdx} className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-700 text-slate-300 text-[10px]">
                              ?{p}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-600">None</span>
                      )}
                    </td>
                    <td className="p-3.5 text-slate-400">
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px]">
                        {ep.source || 'HTML Link'}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                        ep.riskIndicator === 'high'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : ep.riskIndicator === 'medium'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}>
                        {ep.riskIndicator || 'Safe'}
                      </span>
                    </td>
                  </tr>
                ))}

                {filteredEndpoints.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-slate-500">
                      No attack surface endpoints discovered yet. Run a scan against an authorized target.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
