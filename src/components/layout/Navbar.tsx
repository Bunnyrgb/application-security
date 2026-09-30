'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { ShieldCheck, Terminal, ArrowRight, Menu, X, Lock, Cpu, Sparkles } from 'lucide-react';

export default function Navbar() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 w-full border-b border-cyan-500/15 bg-[#030712]/85 backdrop-blur-2xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Logo */}
        <Link href="/" className="flex items-center gap-3 group">
          <div className="relative flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 via-indigo-500 to-emerald-400 p-[1.5px] shadow-lg shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition-all">
            <div className="w-full h-full bg-[#030712] rounded-[9px] flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-cyan-400 transition-transform group-hover:scale-110" />
            </div>
          </div>
          <div className="flex flex-col">
            <span className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5 font-mono">
              SecureLens
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 uppercase tracking-widest font-sans font-semibold">
                AI
              </span>
            </span>
            <span className="text-[10px] text-slate-400 -mt-1 hidden sm:block font-mono">See the Risk. Fix the Risk.</span>
          </div>
        </Link>

        {/* Desktop Links */}
        <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-300">
          <Link href="#features" className="hover:text-cyan-400 transition-colors">
            Features
          </Link>
          <Link href="#technologies" className="hover:text-cyan-400 transition-colors">
            Supported Tech
          </Link>
          <Link href="#pricing" className="hover:text-cyan-400 transition-colors">
            Pricing
          </Link>
          <Link href="#faq" className="hover:text-cyan-400 transition-colors">
            FAQ
          </Link>
        </nav>

        {/* CTA Buttons */}
        <div className="hidden md:flex items-center gap-3">
          <Link 
            href="/auth/login" 
            className="px-4 py-2 text-xs font-mono font-medium text-slate-300 hover:text-white transition-colors"
          >
            Sign In
          </Link>
          <Link
            href="/dashboard"
            className="relative group px-4 py-2 rounded-xl text-xs font-mono font-semibold text-white overflow-hidden shadow-lg shadow-cyan-500/20 transition-all bg-gradient-to-r from-cyan-500 to-indigo-600 hover:opacity-95"
          >
            <div className="relative flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-cyan-200" />
              <span>Launch Console</span>
              <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
            </div>
          </Link>
        </div>

        {/* Mobile menu toggle */}
        <button
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          className="md:hidden p-2 text-slate-400 hover:text-white"
          aria-label="Toggle navigation"
        >
          {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile Drawer */}
      {isMobileMenuOpen && (
        <div className="md:hidden border-b border-slate-800 bg-[#060a18] px-4 pt-3 pb-6 space-y-3">
          <Link 
            href="#features" 
            onClick={() => setIsMobileMenuOpen(false)}
            className="block py-2 text-sm text-slate-300 hover:text-cyan-400"
          >
            Features
          </Link>
          <Link 
            href="#technologies" 
            onClick={() => setIsMobileMenuOpen(false)}
            className="block py-2 text-sm text-slate-300 hover:text-cyan-400"
          >
            Supported Tech
          </Link>
          <Link 
            href="#pricing" 
            onClick={() => setIsMobileMenuOpen(false)}
            className="block py-2 text-sm text-slate-300 hover:text-cyan-400"
          >
            Pricing
          </Link>
          <div className="pt-4 flex flex-col gap-2">
            <Link
              href="/auth/login"
              onClick={() => setIsMobileMenuOpen(false)}
              className="w-full text-center py-2 text-sm text-slate-300 border border-slate-800 rounded-lg"
            >
              Sign In
            </Link>
            <Link
              href="/dashboard"
              onClick={() => setIsMobileMenuOpen(false)}
              className="w-full text-center py-2.5 text-sm font-semibold text-white bg-gradient-to-r from-cyan-500 to-indigo-600 rounded-xl"
            >
              Launch Security Console
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
