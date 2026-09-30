'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Lock, Mail, User, Building, ArrowRight, AlertCircle } from 'lucide-react';
import { useSecurity } from '@/context/SecurityContext';

export default function SignupPage() {
  const router = useRouter();
  const { loginUser } = useSecurity();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [organization, setOrganization] = useState('');
  const [userType, setUserType] = useState<'developer' | 'student' | 'enterprise'>('enterprise');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setErrorMsg('Email and password are required to create your administrator account.');
      return;
    }
    setErrorMsg('');
    setLoading(true);

    setTimeout(() => {
      loginUser({
        fullName: fullName.trim() || undefined,
        email: email.trim(),
        password: password,
        organization: organization.trim() || 'My Organization',
        role: 'owner',
      });
      setLoading(false);
      router.push('/dashboard');
    }, 450);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#030712] text-slate-100 cyber-grid p-4">
      <div className="w-full max-w-lg space-y-6">
        
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
            Set Up Your Administrator Account
          </h2>
          <p className="text-xs text-slate-400">
            Create your account to manage application targets and review security vulnerabilities.
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

          {/* User Type Switcher */}
          <div>
            <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block mb-2">
              Select Your Environment Type
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setUserType('enterprise')}
                className={`py-2 px-3 rounded-xl text-xs font-mono font-medium transition-all ${
                  userType === 'enterprise'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                    : 'bg-[#050814] border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                Enterprise / Org
              </button>
              <button
                type="button"
                onClick={() => setUserType('developer')}
                className={`py-2 px-3 rounded-xl text-xs font-mono font-medium transition-all ${
                  userType === 'developer'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                    : 'bg-[#050814] border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                Developer
              </button>
              <button
                type="button"
                onClick={() => setUserType('student')}
                className={`py-2 px-3 rounded-xl text-xs font-mono font-medium transition-all ${
                  userType === 'student'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                    : 'bg-[#050814] border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                Student / Lab
              </button>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block mb-1">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                    placeholder="e.g. Alex Hunter"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block mb-1">
                  Organization / Company
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                    placeholder="e.g. CyberDefense Ltd"
                  />
                </div>
              </div>
            </div>

            <div>
              <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block mb-1">
                Admin Email Address *
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  placeholder="admin@yourcompany.com"
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block mb-1">
                Password *
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-[#050814] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  placeholder="Create your admin password"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl text-xs font-mono font-semibold text-white bg-gradient-to-r from-cyan-500 via-indigo-600 to-cyan-500 hover:opacity-95 shadow-md shadow-cyan-500/20 transition-all flex items-center justify-center gap-2"
            >
              <span>{loading ? 'Creating Account...' : 'Complete Setup & Open Admin Console'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>

          <div className="text-center pt-1">
            <span className="text-xs text-slate-400">
              Already have credentials?{' '}
              <Link href="/auth/login" className="text-cyan-400 hover:underline font-mono font-semibold">
                Sign in
              </Link>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
