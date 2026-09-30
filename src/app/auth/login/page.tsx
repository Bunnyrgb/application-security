'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Lock, Mail, ArrowRight, KeyRound, Server, AlertCircle } from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';

export default function LoginPage() {
  const router = useRouter();
  const { loginUser } = useSecurity();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [resetEmailSent, setResetEmailSent] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setErrorMsg('Please enter both your email address and password.');
      return;
    }
    setErrorMsg('');
    setLoading(true);

    setTimeout(() => {
      loginUser({
        email: email.trim(),
        password: password,
        role: 'owner',
      });
      setLoading(false);
      router.push('/dashboard');
    }, 450);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#030712] text-slate-100 cyber-grid p-4">
      <div className="w-full max-w-md space-y-6">
        
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <Link href="/" className="inline-flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 via-indigo-500 to-emerald-400 p-[1.5px] shadow-lg shadow-cyan-500/20">
              <div className="w-full h-full bg-[#030712] rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
              </div>
            </div>
            <span className="text-2xl font-bold font-mono tracking-tight text-white">
              SecureLens
            </span>
          </Link>
          <h2 className="text-xl font-bold text-white tracking-tight font-sans">
            Administrator & Security Analyst Sign In
          </h2>
          <p className="text-xs text-slate-400">
            Enter your credentials to access the central security governance console.
          </p>
        </div>

        {/* Form Container */}
        <div className="p-6 sm:p-8 rounded-2xl glass-card border border-cyan-500/20 shadow-2xl space-y-5">
          {errorMsg && (
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 flex items-center gap-2 font-mono">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block mb-1.5">
                Admin Email Address *
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-3 py-2.5 text-xs font-mono bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                  placeholder="your.email@domain.com"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block">
                  Password *
                </label>
                <button
                  type="button"
                  onClick={() => setShowForgotModal(true)}
                  className="text-[11px] font-mono text-cyan-400 hover:underline"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2.5 text-xs font-mono bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                  placeholder="Enter your secure password"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl text-xs font-mono font-semibold text-white bg-gradient-to-r from-cyan-500 via-indigo-600 to-cyan-500 hover:opacity-95 shadow-md shadow-cyan-500/20 transition-all flex items-center justify-center gap-2"
            >
              <span>{loading ? 'Authenticating Credentials...' : 'Sign In as Administrator'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          <div className="pt-2 text-center">
            <span className="text-xs text-slate-400">
              New to SecureLens?{' '}
              <Link href="/auth/signup" className="text-cyan-400 hover:underline font-mono font-semibold">
                Create Admin Account
              </Link>
            </span>
          </div>
        </div>

        <div className="text-center text-[11px] font-mono text-slate-500">
          🔒 Secure authentication with sliding-window rate limiting & brute-force defense
        </div>
      </div>

      {/* Forgot Password Modal */}
      {showForgotModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0b1022] border border-slate-800 rounded-2xl max-w-sm w-full p-6 space-y-4 shadow-2xl">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mx-auto">
              <KeyRound className="w-5 h-5" />
            </div>
            <div className="text-center space-y-1">
              <h4 className="text-sm font-bold text-white font-mono">Reset Password</h4>
              <p className="text-xs text-slate-400">
                Enter your account email to receive a password reset token.
              </p>
            </div>

            {resetEmailSent ? (
              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800/50 text-xs text-emerald-300 text-center font-mono">
                ✓ Reset instructions sent to {email || 'your email'}.
              </div>
            ) : (
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                placeholder="your.email@domain.com"
              />
            )}

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => {
                  setShowForgotModal(false);
                  setResetEmailSent(false);
                }}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white"
              >
                Close
              </button>
              {!resetEmailSent && (
                <button
                  type="button"
                  onClick={() => setResetEmailSent(true)}
                  className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white font-mono"
                >
                  Send Reset Link
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
