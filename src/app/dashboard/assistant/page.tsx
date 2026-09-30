'use client';

import React, { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { Bot, Sparkles, ShieldCheck, Terminal } from 'lucide-react';
import SecureLensAIChat from '@/components/ai/SecureLensAIChat';

function AssistantContent() {
  const searchParams = useSearchParams();
  const vulnParam = searchParams.get('vuln') || undefined;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-cyan mb-1">
            <Bot className="w-4 h-4" />
            <span>AI-Powered Security Co-Pilot</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            SecureLens AI Assistant
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Ask technical or executive security questions grounded directly in your application&apos;s AST findings and CVSS risk parameters.
          </p>
        </div>
      </div>

      <SecureLensAIChat initialVulnId={vulnParam} />
    </div>
  );
}

export default function AssistantPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-xs text-slate-400 font-mono">Loading SecureLens AI Co-Pilot...</div>}>
      <AssistantContent />
    </Suspense>
  );
}
