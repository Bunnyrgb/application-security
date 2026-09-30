import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { SeverityLevel, TriageStatus } from "@/types/security";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getSeverityColor(severity: SeverityLevel) {
  switch (severity) {
    case 'critical':
      return {
        bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
        badge: 'bg-rose-950/80 text-rose-300 border-rose-700/50',
        dot: 'bg-rose-500',
        glow: 'shadow-[0_0_12px_rgba(244,63,94,0.3)]',
      };
    case 'high':
      return {
        bg: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
        badge: 'bg-orange-950/80 text-orange-300 border-orange-700/50',
        dot: 'bg-orange-500',
        glow: 'shadow-[0_0_12px_rgba(249,115,22,0.3)]',
      };
    case 'medium':
      return {
        bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
        badge: 'bg-amber-950/80 text-amber-300 border-amber-700/50',
        dot: 'bg-amber-500',
        glow: 'shadow-[0_0_12px_rgba(245,158,11,0.3)]',
      };
    case 'low':
      return {
        bg: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
        badge: 'bg-blue-950/80 text-blue-300 border-blue-700/50',
        dot: 'bg-blue-500',
        glow: 'shadow-[0_0_12px_rgba(59,130,246,0.3)]',
      };
    case 'informational':
    default:
      return {
        bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
        badge: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/50',
        dot: 'bg-emerald-500',
        glow: 'shadow-[0_0_12px_rgba(16,185,129,0.3)]',
      };
  }
}

export function getScoreGrade(score: number): { label: string; color: string; ringColor: string } {
  if (score >= 90) return { label: 'Excellent Posture', color: 'text-emerald-400', ringColor: '#10b981' };
  if (score >= 80) return { label: 'Good Posture', color: 'text-cyber-cyan', ringColor: '#00f0ff' };
  if (score >= 65) return { label: 'Needs Attention', color: 'text-amber-400', ringColor: '#f59e0b' };
  if (score >= 45) return { label: 'High Risk', color: 'text-orange-500', ringColor: '#f97316' };
  return { label: 'Critical Risk', color: 'text-rose-500', ringColor: '#f43f5e' };
}

export function getTriageBadge(status: TriageStatus) {
  switch (status) {
    case 'fixed':
      return { label: 'Resolved / Fixed', bg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' };
    case 'false_positive':
      return { label: 'False Positive', bg: 'bg-purple-500/20 text-purple-300 border-purple-500/40' };
    case 'accepted_risk':
      return { label: 'Risk Accepted', bg: 'bg-amber-500/20 text-amber-300 border-amber-500/40' };
    case 'confirmed':
    default:
      return { label: 'Active Finding', bg: 'bg-rose-500/20 text-rose-300 border-rose-500/40' };
  }
}

export function formatDate(dateString?: string): string {
  if (!dateString) return 'Just now';
  try {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(date);
  } catch {
    return dateString;
  }
}
