'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import Navbar from '@/components/layout/Navbar';
import Footer from '@/components/layout/Footer';
import { 
  ShieldCheck, 
  Terminal, 
  ArrowRight, 
  CheckCircle2, 
  Sparkles, 
  Radar, 
  Lock, 
  Boxes, 
  Cpu, 
  TrendingUp, 
  ChevronRight,
  Code2,
  FileCheck,
  AlertOctagon,
  Eye,
  Zap,
  Activity,
  Layers,
  Flame,
  Check
} from 'lucide-react';
import { SAMPLE_VULNERABLE_CODE_SNIPPETS } from '@/lib/demo-data';

export default function LandingPage() {
  const [activeTab, setActiveTab] = useState<'express' | 'python' | 'react'>('express');
  const [faqOpen, setFaqOpen] = useState<number | null>(0);

  const faqs = [
    {
      q: 'Does SecureLens execute or run my uploaded source code?',
      a: 'Never. SecureLens utilizes strictly isolated, non-executing static analysis (SAST) pipelines and Abstract Syntax Tree (AST) grammar parsing. Uploaded code and repositories are analyzed inside sandboxes with zero network egress and wiped immediately upon audit finalization.'
    },
    {
      q: 'How does SecureLens AI provide remediation advice without hallucinations?',
      a: 'SecureLens AI is contextually grounded in your specific AST findings, detected frameworks, and verified CWE/OWASP rulesets. It receives the exact file location, vulnerable line snippet, and syntax tree before generating recommended code diffs.'
    },
    {
      q: 'What vulnerability standards are mapped in the reports?',
      a: 'Every finding is mapped to industry benchmarks: OWASP Top 10 (2021), OWASP API Security Top 10, CWE/SANS Top 25, and CVSS v3.1 scoring.'
    },
    {
      q: 'Can I connect private GitHub and GitLab repositories?',
      a: 'Yes. SecureLens supports short-lived Personal Access Tokens and OAuth integrations. Credentials are used ephemerally in memory to clone specific branches and are never stored in plain text.'
    },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-[#030712] text-slate-100 cyber-grid selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar />

      {/* Hero Section with Ambient Glows */}
      <section className="relative pt-24 pb-20 md:pt-36 md:pb-32 overflow-hidden">
        {/* Futuristic Gradient Aura */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[400px] bg-gradient-to-tr from-indigo-600/20 via-cyan-500/20 to-teal-400/10 blur-[130px] pointer-events-none rounded-full" />
        <div className="absolute top-1/3 right-10 w-96 h-96 bg-purple-600/10 blur-[120px] pointer-events-none rounded-full" />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 text-center space-y-8">
          
          {/* Holographic Badge */}
          <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-slate-900/80 border border-cyan-500/40 text-xs font-mono text-cyan-300 shadow-lg shadow-cyan-500/10 backdrop-blur-md">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
            </span>
            <span className="font-semibold tracking-wide">SECURELENS ENGINE v2.4</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">SAST • SCA • AI REMEDIATION</span>
          </div>

          {/* Heading */}
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-[1.08] font-sans">
            Find Security Problems <br />
            <span className="gradient-text-hero">
              Before Attackers Do.
            </span>
          </h1>

          {/* Tagline */}
          <p className="text-base sm:text-xl text-slate-300/90 max-w-2xl mx-auto leading-relaxed font-sans font-normal">
            SecureLens automatically analyzes your code, dependencies, APIs, and configuration to identify vulnerabilities, risky packages, and exposed secrets — then explains exactly how to fix them.
          </p>

          {/* CTA Buttons */}
          <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/dashboard/new-scan"
              className="w-full sm:w-auto px-8 py-4 rounded-xl font-semibold text-sm text-white bg-gradient-to-r from-cyan-500 via-indigo-600 to-cyan-500 hover:opacity-95 shadow-xl shadow-cyan-500/25 transition-all flex items-center justify-center gap-2.5 font-mono group"
            >
              <Radar className="w-4 h-4 text-cyan-200" />
              <span>Start Security Scan</span>
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
            </Link>

            <Link
              href="/dashboard"
              className="w-full sm:w-auto px-8 py-4 rounded-xl font-semibold text-sm text-slate-200 bg-[#0d1326]/80 hover:bg-[#121a36] border border-slate-700/70 hover:border-cyan-500/50 shadow-lg transition-all flex items-center justify-center gap-2.5 font-mono backdrop-blur-sm"
            >
              <Eye className="w-4 h-4 text-cyan-400" />
              <span>Explore Demo Project</span>
            </Link>
          </div>

          {/* Trust Metrics Bar */}
          <div className="pt-12 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto border-t border-slate-800/80">
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/60 backdrop-blur-sm">
              <div className="text-2xl sm:text-3xl font-mono font-bold text-white">412+</div>
              <div className="text-xs text-slate-400 mt-1">SAST Rules & Signatures</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/60 backdrop-blur-sm">
              <div className="text-2xl sm:text-3xl font-mono font-bold text-cyan-400">99.4%</div>
              <div className="text-xs text-slate-400 mt-1">False Positive Reduction</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/60 backdrop-blur-sm">
              <div className="text-2xl sm:text-3xl font-mono font-bold text-emerald-400">&lt; 2.5s</div>
              <div className="text-xs text-slate-400 mt-1">Average AST Scan Time</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/60 backdrop-blur-sm">
              <div className="text-2xl sm:text-3xl font-mono font-bold text-indigo-400">OWASP / CWE</div>
              <div className="text-xs text-slate-400 mt-1">Standardized Frameworks</div>
            </div>
          </div>
        </div>
      </section>

      {/* Interactive Code Inspection & Fix Demo */}
      <section className="py-16 bg-[#040817]/80 border-y border-slate-800/80 relative">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-10 space-y-2">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-xs font-mono">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>LIVE INTERACTIVE HEURISTICS</span>
            </div>
            <h2 className="text-2xl sm:text-4xl font-extrabold text-white">
              See How SecureLens Detects & Fixes Weaknesses
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
              Test simulated security scenarios and inspect drop-in secure code refactors generated by the scanner.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800/90 bg-[#080d1e] overflow-hidden shadow-2xl neon-border">
            {/* Header Tabs */}
            <div className="flex flex-wrap items-center justify-between px-4 py-3 bg-[#0c1228] border-b border-slate-800 text-xs font-mono gap-2">
              <div className="flex items-center gap-2">
                <span className="text-slate-400 hidden sm:inline">Scenario:</span>
                <button
                  onClick={() => setActiveTab('express')}
                  className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${activeTab === 'express' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm' : 'text-slate-400 hover:text-white'}`}
                >
                  Node.js API (SQLi + Secrets)
                </button>
                <button
                  onClick={() => setActiveTab('python')}
                  className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${activeTab === 'python' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm' : 'text-slate-400 hover:text-white'}`}
                >
                  Python Flask (SQLi + Hash)
                </button>
                <button
                  onClick={() => setActiveTab('react')}
                  className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${activeTab === 'react' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm' : 'text-slate-400 hover:text-white'}`}
                >
                  React Frontend (XSS)
                </button>
              </div>

              <Link
                href="/dashboard/new-scan"
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
              >
                <span>Launch Scanner Console</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {/* Split Screen View */}
            <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-800">
              {/* Input Code */}
              <div className="p-5 bg-[#050814]">
                <div className="text-xs font-mono text-slate-400 mb-2.5 flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
                    <Code2 className="w-4 h-4 text-cyan-400" />
                    Input Source Code (AST Parsed)
                  </span>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40">
                    Defects Identified
                  </span>
                </div>
                <pre className="text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto max-h-[320px] p-3 rounded-lg bg-[#02050e] border border-slate-900">
                  <code>
                    {activeTab === 'express' && SAMPLE_VULNERABLE_CODE_SNIPPETS.express_api}
                    {activeTab === 'python' && SAMPLE_VULNERABLE_CODE_SNIPPETS.python_flask}
                    {activeTab === 'react' && SAMPLE_VULNERABLE_CODE_SNIPPETS.react_frontend}
                  </code>
                </pre>
              </div>

              {/* SecureLens Remediation */}
              <div className="p-5 bg-[#090e24] space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
                    <span className="text-xs font-mono font-bold text-rose-400 uppercase tracking-wider">
                      CWE-89: SQL Injection Flaw
                    </span>
                  </div>
                  <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700/50">
                    CRITICAL (9.8)
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  User-controlled input is directly concatenated into database query without parameterization or escaping.
                </p>

                <div className="p-3.5 rounded-xl bg-[#060a18] border border-cyan-500/30 space-y-2">
                  <span className="text-xs font-mono text-emerald-400 font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    Remediated Implementation (Parameterized):
                  </span>
                  <pre className="text-xs font-mono text-cyan-200 overflow-x-auto p-2.5 rounded bg-[#030612] border border-slate-900">
                    <code>
{activeTab === 'express' && `const sql = "SELECT * FROM accounts WHERE id = $1";
const result = await db.query(sql, [accountId]);`}
{activeTab === 'python' && `cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))`}
{activeTab === 'react' && `<p className="comment-text">{commentData.rawBody}</p>`}
                    </code>
                  </pre>
                </div>

                <div className="pt-2 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Score Impact: +22 pts after fix</span>
                  <Link
                    href="/dashboard"
                    className="text-cyan-400 hover:underline flex items-center gap-1 font-semibold"
                  >
                    <span>View in Dashboard</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4 Pillars: Detect, Understand, Fix, Improve */}
      <section id="features" className="py-24 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-xs font-mono">
            <span>APPLICATION SECURITY LIFECYCLE</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Built for Modern Developers & Startups
          </h2>
          <p className="text-sm sm:text-base text-slate-400 leading-relaxed">
            Traditional security tools generate hundreds of false positives with no clear path to remediation. SecureLens guides you end-to-end.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* 1. Detect */}
          <div className="glass-card p-6 rounded-2xl space-y-4">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-md shadow-cyan-500/10">
              <Radar className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-white font-sans">
              Detect
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Discover potential security weaknesses across source code, Git repositories, ZIP archives, API specs, and configuration files.
            </p>
            <ul className="text-[11px] font-mono text-slate-400 space-y-1.5 pt-1">
              <li className="flex items-center gap-1.5 text-cyan-300/90">• SAST Static Analysis</li>
              <li className="flex items-center gap-1.5 text-cyan-300/90">• Secret & Key Scraper</li>
              <li className="flex items-center gap-1.5 text-cyan-300/90">• SCA Dependency Audit</li>
            </ul>
          </div>

          {/* 2. Understand */}
          <div className="glass-card p-6 rounded-2xl space-y-4">
            <div className="w-12 h-12 rounded-xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shadow-md shadow-indigo-500/10">
              <Sparkles className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-white font-sans">
              Understand
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              See the risk explained in simple, clear language. Understand why an issue is dangerous, its impact, and its OWASP/CWE classification.
            </p>
            <ul className="text-[11px] font-mono text-slate-400 space-y-1.5 pt-1">
              <li className="flex items-center gap-1.5 text-indigo-300/90">• Contextual AI Explainer</li>
              <li className="flex items-center gap-1.5 text-indigo-300/90">• Plain-English summaries</li>
              <li className="flex items-center gap-1.5 text-indigo-300/90">• Business & compliance impact</li>
            </ul>
          </div>

          {/* 3. Fix */}
          <div className="glass-card p-6 rounded-2xl space-y-4">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-md shadow-emerald-500/10">
              <Code2 className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-white font-sans">
              Fix
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Get developer-friendly remediation guidance with drop-in, copy-pasteable code examples tailored to your exact programming language.
            </p>
            <ul className="text-[11px] font-mono text-slate-400 space-y-1.5 pt-1">
              <li className="flex items-center gap-1.5 text-emerald-300/90">• Before / After diff view</li>
              <li className="flex items-center gap-1.5 text-emerald-300/90">• Parameterized queries & ORMs</li>
              <li className="flex items-center gap-1.5 text-emerald-300/90">• Secret rotation guides</li>
            </ul>
          </div>

          {/* 4. Improve */}
          <div className="glass-card p-6 rounded-2xl space-y-4">
            <div className="w-12 h-12 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 shadow-md shadow-purple-500/10">
              <TrendingUp className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-white font-sans">
              Improve
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Track your security score evolution over time. Compare scans, verify resolved issues, and generate executive audit reports.
            </p>
            <ul className="text-[11px] font-mono text-slate-400 space-y-1.5 pt-1">
              <li className="flex items-center gap-1.5 text-purple-300/90">• Dynamic 0-100 scoring</li>
              <li className="flex items-center gap-1.5 text-purple-300/90">• Scan comparison diffs</li>
              <li className="flex items-center gap-1.5 text-purple-300/90">• Executive PDF exports</li>
            </ul>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 border-t border-slate-800/80">
        <div className="text-center max-w-2xl mx-auto mb-16 space-y-3">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-xs font-mono">
            <span>TRANSPARENT PLANS</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
            Security That Scales With You
          </h2>
          <p className="text-sm text-slate-400">
            Start scanning for free. Scale to advanced AI security analysis and continuous CI/CD monitoring.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Free Tier */}
          <div className="glass-card p-8 rounded-2xl flex flex-col justify-between space-y-6">
            <div className="space-y-4">
              <span className="text-xs font-mono uppercase text-slate-400 font-bold">Community & Students</span>
              <div className="text-3xl font-extrabold font-mono text-white">$0 <span className="text-xs text-slate-400 font-normal">/ month</span></div>
              <p className="text-xs text-slate-300">
                Essential security scanning for individual developers, hobby projects, and students.
              </p>
              <ul className="space-y-2.5 text-xs text-slate-300 pt-2">
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Up to 10 scans / month</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Core SAST Vulnerability Detection</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Basic Security Score & Report</span>
                </li>
              </ul>
            </div>
            <Link
              href="/dashboard/new-scan"
              className="w-full py-2.5 rounded-xl text-xs font-mono font-semibold text-center border border-slate-700 hover:bg-slate-800 text-slate-200 transition-colors"
            >
              Start Free Scan
            </Link>
          </div>

          {/* Developer Pro Tier */}
          <div className="glass-card p-8 rounded-2xl border-2 border-cyan-500/60 shadow-2xl shadow-cyan-500/15 flex flex-col justify-between space-y-6 relative bg-gradient-to-b from-[#0f1733] to-[#070b1a]">
            <div className="absolute -top-3.5 right-6 px-3.5 py-0.5 rounded-full bg-gradient-to-r from-cyan-500 to-indigo-600 text-[10px] font-mono font-bold uppercase text-white tracking-wider shadow-md">
              Most Popular
            </div>
            <div className="space-y-4">
              <span className="text-xs font-mono uppercase text-cyan-400 font-bold">Developer Pro</span>
              <div className="text-3xl font-extrabold font-mono text-white">$29 <span className="text-xs text-slate-400 font-normal">/ month</span></div>
              <p className="text-xs text-slate-300">
                Full-featured security platform for independent builders, startups, and consulting teams.
              </p>
              <ul className="space-y-2.5 text-xs text-slate-300 pt-2">
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Unlimited Security Scans</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>SecureLens AI Remediation Assistant</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Software Composition Analysis (SCA)</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Executive PDF Report Downloads</span>
                </li>
              </ul>
            </div>
            <Link
              href="/dashboard/new-scan"
              className="w-full py-3 rounded-xl text-xs font-mono font-semibold text-center bg-gradient-to-r from-cyan-500 via-indigo-600 to-cyan-500 text-white shadow-lg shadow-cyan-500/25 hover:opacity-95 transition-opacity"
            >
              Get Started with Pro
            </Link>
          </div>

          {/* Business Tier */}
          <div className="glass-card p-8 rounded-2xl flex flex-col justify-between space-y-6">
            <div className="space-y-4">
              <span className="text-xs font-mono uppercase text-slate-400 font-bold">Business & Org</span>
              <div className="text-3xl font-extrabold font-mono text-white">$149 <span className="text-xs text-slate-400 font-normal">/ month</span></div>
              <p className="text-xs text-slate-300">
                Organization-wide security governance, RBAC team collaboration, and CI/CD gating.
              </p>
              <ul className="space-y-2.5 text-xs text-slate-300 pt-2">
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Team Collaboration (Unlimited Seats)</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Role-Based Access (Owner, Analyst, Dev)</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Continuous Git Webhooks & Alerts</span>
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-cyan-400" />
                  <span>Custom Compliance Exports (SOC 2, PCI)</span>
                </li>
              </ul>
            </div>
            <Link
              href="/dashboard/settings"
              className="w-full py-2.5 rounded-xl text-xs font-mono font-semibold text-center border border-slate-700 hover:bg-slate-800 text-slate-200 transition-colors"
            >
              Explore Business
            </Link>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section id="faq" className="py-20 bg-[#040816]/60 border-t border-slate-800/80">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
          <div className="text-center space-y-2">
            <h2 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold">
              FREQUENTLY ASKED QUESTIONS
            </h2>
            <h3 className="text-2xl sm:text-3xl font-bold text-white">
              Everything You Need to Know
            </h3>
          </div>

          <div className="space-y-3">
            {faqs.map((faq, index) => (
              <div 
                key={index}
                className="glass-card rounded-xl overflow-hidden"
              >
                <button
                  onClick={() => setFaqOpen(faqOpen === index ? null : index)}
                  className="w-full p-4 text-left text-sm font-semibold text-white flex items-center justify-between hover:text-cyan-400 transition-colors"
                >
                  <span>{faq.q}</span>
                  <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform ${faqOpen === index ? 'rotate-90 text-cyan-400' : ''}`} />
                </button>
                {faqOpen === index && (
                  <div className="px-4 pb-4 text-xs text-slate-300 leading-relaxed border-t border-slate-800/60 pt-3">
                    {faq.a}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Final Pre-Footer Call to Action */}
      <section className="py-24 relative overflow-hidden text-center">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Ready to Secure Your Applications?
          </h2>
          <p className="text-slate-300 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
            Run your first automated security scan in less than 30 seconds. Identify vulnerabilities before your next production deployment.
          </p>
          <div className="pt-2 flex justify-center">
            <Link
              href="/dashboard/new-scan"
              className="px-9 py-4 rounded-xl font-semibold text-sm text-white bg-gradient-to-r from-cyan-500 via-indigo-600 to-cyan-500 hover:opacity-95 shadow-xl shadow-cyan-500/25 transition-all font-mono"
            >
              Start Security Scan Free
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}
