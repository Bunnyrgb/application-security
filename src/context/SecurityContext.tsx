'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { 
  Application, 
  Scan, 
  Vulnerability, 
  DependencyFinding, 
  TriageStatus, 
  ScanType, 
  UserProfile, 
  AIChatMessage,
  ScanTelemetryStep,
  AuditLog,
  ScannerRuleConfig
} from '@/types/security';
import { analyzeSecurityContent } from '@/lib/scanner-engine';
import { generateAIAnswer } from '@/lib/ai-assistant-engine';
import { DEMO_APPLICATION, INITIAL_VULNERABILITIES, INITIAL_DEPENDENCIES, DEMO_SCAN_HISTORY } from '@/lib/demo-data';

export interface AdminUser {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'security_analyst' | 'developer' | 'auditor';
  status: 'active' | 'suspended' | 'invited';
  last_login: string;
  created_at: string;
}

interface SecurityContextType {
  applications: Application[];
  activeApp: Application | null;
  vulnerabilities: Vulnerability[];
  dependencies: DependencyFinding[];
  scanHistory: Scan[];
  activeScan: Scan | null;
  isScanning: boolean;
  scanProgress: number;
  currentStepMessage: string;
  telemetryLogs: ScanTelemetryStep[];
  userProfile: UserProfile;
  aiMessages: AIChatMessage[];
  isAiThinking: boolean;
  scoreComparison: { before: number; after: number };
  
  // Admin & Governance state
  adminUsers: AdminUser[];
  auditLogs: AuditLog[];
  scannerRules: ScannerRuleConfig[];
  
  // Actions
  selectApplication: (appId: string) => void;
  setActiveScan: (scan: Scan | null) => void;
  addNewApplication: (app: Partial<Application>) => Application;
  deleteApplication: (appId: string) => void;
  updateVulnerabilityStatus: (vulnId: string, status: TriageStatus, reason?: string) => void;
  runNewScan: (type: ScanType, target: string, content?: string, appOverrideId?: string) => Promise<Scan>;
  sendAIMessage: (message: string, selectedVulnId?: string) => Promise<void>;
  addAuditLog: (action: string, target: string, severity?: 'info' | 'warning' | 'critical') => void;
  
  // Admin Actions
  addAdminUser: (user: Omit<AdminUser, 'id' | 'created_at' | 'last_login'>) => void;
  updateUserRole: (userId: string, role: AdminUser['role']) => void;
  toggleUserStatus: (userId: string) => void;
  deleteUser: (userId: string) => void;
  toggleScannerRule: (ruleId: string) => void;
  
  // User & Auth actions
  loginUser: (credentials: { email: string; password?: string; fullName?: string; organization?: string; role?: UserProfile['role'] }) => void;
  logoutUser: () => void;
  updateUserProfile: (profile: Partial<UserProfile>) => void;
  
  // State resets
  clearAllData: () => void;
  loadDemoData: () => void;
  fixAllIssues: () => void;
}

const DEFAULT_SCANNER_RULES: ScannerRuleConfig[] = [
  { id: 'rule_sqli', name: 'SQL Injection Detection', category: 'Input Security', enabled: true, severity: 'critical', description: 'Detects unsanitized input concatenated into SQL queries.' },
  { id: 'rule_secrets', name: 'High-Entropy Secret Hunter', category: 'Secrets', enabled: true, severity: 'critical', description: 'Detects Stripe, AWS, JWT, and cloud credentials with masking.' },
  { id: 'rule_ratelimit', name: 'Missing Authentication Rate Limiting', category: 'API Security', enabled: true, severity: 'high', description: 'Checks whether login/auth routes have brute-force throttling.' },
  { id: 'rule_jwt', name: 'Insecure JWT Signature Verification', category: 'Authentication', enabled: true, severity: 'high', description: 'Detects none algorithm and missing expiration checks.' },
  { id: 'rule_idor', name: 'Broken Access Control / IDOR', category: 'Authorization', enabled: true, severity: 'high', description: 'Flags unverified URL object ID retrievals.' },
  { id: 'rule_xss', name: 'Cross-Site Scripting (XSS)', category: 'Input Security', enabled: true, severity: 'medium', description: 'Detects dangerouslySetInnerHTML and raw HTML rendering.' },
  { id: 'rule_cors', name: 'Wildcard CORS Origin With Credentials', category: 'API Security', enabled: true, severity: 'medium', description: 'Flags permissive cross-origin configuration.' },
  { id: 'rule_crypto', name: 'Weak Cryptographic Hashing (MD5/SHA1)', category: 'Cryptography', enabled: true, severity: 'medium', description: 'Flags deprecated hashing functions.' },
];

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

export function SecurityProvider({ children }: { children: ReactNode }) {
  // Start 100% Fresh: empty applications or loaded from localStorage!
  const [applications, setApplications] = useState<Application[]>([]);
  const [activeApp, setActiveApp] = useState<Application | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [dependencies, setDependencies] = useState<DependencyFinding[]>([]);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  
  // Scanning state
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStepMessage, setCurrentStepMessage] = useState('');
  const [telemetryLogs, setTelemetryLogs] = useState<ScanTelemetryStep[]>([]);
  const [scoreComparison, setScoreComparison] = useState({ before: 100, after: 100 });

  // User Profile
  const [userProfile, setUserProfile] = useState<UserProfile>({
    id: 'usr_admin_01',
    email: 'admin@securelens.local',
    full_name: 'System Administrator',
    organization: 'Security Operations Center',
    role: 'owner',
    user_type: 'enterprise',
    created_at: new Date().toISOString(),
  });

  // Admin users list
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([
    {
      id: 'usr_admin_01',
      name: 'System Administrator',
      email: 'admin@securelens.local',
      role: 'admin',
      status: 'active',
      last_login: 'Just now',
      created_at: new Date().toISOString(),
    },
    {
      id: 'usr_analyst_02',
      name: 'Security Lead',
      email: 'security.lead@securelens.local',
      role: 'security_analyst',
      status: 'active',
      last_login: '2 hours ago',
      created_at: new Date().toISOString(),
    }
  ]);

  // Audit Logs
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([
    {
      id: 'log_init',
      user_email: 'admin@securelens.local',
      action: 'SECURITY_CONSOLE_INITIALIZED',
      target: 'System Daemon v2.4',
      ip_address: '127.0.0.1',
      timestamp: new Date().toISOString(),
      severity: 'info',
    }
  ]);

  // Scanner Rules
  const [scannerRules, setScannerRules] = useState<ScannerRuleConfig[]>(DEFAULT_SCANNER_RULES);

  // AI Chat
  const [aiMessages, setAiMessages] = useState<AIChatMessage[]>([
    {
      id: 'msg_welcome',
      sender: 'assistant',
      content: 'Welcome to **SecureLens Administration & Security Console**. The workspace is currently fresh. You can create your first application target, paste source code to scan, or manage scanner rules in the Admin Panel.',
      timestamp: new Date().toISOString(),
      suggested_actions: [
        'How do I run my first security scan?',
        'What vulnerabilities does SecureLens detect?',
        'How does the rate limiting rule work?'
      ]
    }
  ]);
  const [isAiThinking, setIsAiThinking] = useState(false);

  // Load from localStorage on initial mount if saved
  useEffect(() => {
    try {
      const savedUser = localStorage.getItem('securelens_user');
      const savedAdminUsers = localStorage.getItem('securelens_admin_users');
      const savedApps = localStorage.getItem('securelens_apps');
      const savedHistory = localStorage.getItem('securelens_scans');
      const savedVulns = localStorage.getItem('securelens_vulns');

      if (savedUser) {
        const parsedUser = JSON.parse(savedUser);
        if (parsedUser && parsedUser.email) {
          setUserProfile(parsedUser);
        }
      }
      if (savedAdminUsers) {
        const parsedAdmin = JSON.parse(savedAdminUsers);
        if (Array.isArray(parsedAdmin) && parsedAdmin.length > 0) {
          setAdminUsers(parsedAdmin);
        }
      }
      if (savedApps) {
        const parsed = JSON.parse(savedApps);
        if (Array.isArray(parsed) && parsed.length > 0) {
          setApplications(parsed);
          setActiveApp(parsed[0]);
        }
      }
      if (savedHistory) {
        const parsedHistory = JSON.parse(savedHistory);
        if (Array.isArray(parsedHistory) && parsedHistory.length > 0) {
          setScanHistory(parsedHistory);
          setActiveScan(parsedHistory[0]);
        }
      }
      if (savedVulns) {
        const parsedVulns = JSON.parse(savedVulns);
        if (Array.isArray(parsedVulns)) {
          setVulnerabilities(parsedVulns);
        }
      }
    } catch {
      // ignore storage errors
    }
  }, []);

  // Save to localStorage when state updates
  useEffect(() => {
    try {
      localStorage.setItem('securelens_apps', JSON.stringify(applications));
      localStorage.setItem('securelens_scans', JSON.stringify(scanHistory));
      localStorage.setItem('securelens_vulns', JSON.stringify(vulnerabilities));
      localStorage.setItem('securelens_admin_users', JSON.stringify(adminUsers));
    } catch {
      // ignore storage write errors
    }
  }, [applications, scanHistory, vulnerabilities, adminUsers]);

  const addAuditLog = (action: string, target: string, severity: 'info' | 'warning' | 'critical' = 'info') => {
    const newLog: AuditLog = {
      id: `log_${Date.now()}`,
      user_email: userProfile.email,
      action,
      target,
      ip_address: '127.0.0.1',
      timestamp: new Date().toISOString(),
      severity,
    };
    setAuditLogs(prev => [newLog, ...prev]);
  };

  const selectApplication = (appId: string) => {
    const found = applications.find(a => a.id === appId);
    if (found) {
      setActiveApp(found);
      addAuditLog('APPLICATION_SELECTED', found.name, 'info');
    }
  };

  const addNewApplication = (appData: Partial<Application>): Application => {
    const newApp: Application = {
      id: `app_${Date.now()}`,
      user_id: userProfile.id,
      name: appData.name || 'Custom Application',
      description: appData.description || 'Application registered for security posture analysis.',
      repository_url: appData.repository_url,
      environment: appData.environment || 'production',
      technology_stack: appData.technology_stack || [
        { category: 'Language', name: 'TypeScript', confidence: 95 },
        { category: 'Backend', name: 'Node.js', confidence: 90 },
      ],
      current_score: 100,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 0,
      last_scanned_at: new Date().toISOString(),
      total_scans: 0,
      created_at: new Date().toISOString(),
    };

    setApplications(prev => [newApp, ...prev]);
    setActiveApp(newApp);
    addAuditLog('APPLICATION_REGISTERED', newApp.name, 'info');
    return newApp;
  };

  const deleteApplication = (appId: string) => {
    const appToDelete = applications.find(a => a.id === appId);
    const updated = applications.filter(a => a.id !== appId);
    setApplications(updated);
    if (activeApp?.id === appId) {
      setActiveApp(updated[0] || null);
    }
    setVulnerabilities(prev => prev.filter(v => v.application_id !== appId));
    addAuditLog('APPLICATION_DELETED', appToDelete?.name || appId, 'warning');
  };

  const recalculateSecurityScore = (currentVulns: Vulnerability[], targetAppId: string) => {
    let crit = 0;
    let high = 0;
    let med = 0;
    let low = 0;
    let info = 0;

    currentVulns.forEach(v => {
      if (v.application_id === targetAppId && v.status === 'confirmed') {
        if (v.severity === 'critical') crit++;
        else if (v.severity === 'high') high++;
        else if (v.severity === 'medium') med++;
        else if (v.severity === 'low') low++;
        else info++;
      }
    });

    const penalty = (crit * 22) + (high * 12) + (med * 6) + (low * 2);
    const newScore = Math.max(15, Math.min(100, 100 - penalty));

    if (activeApp && activeApp.id === targetAppId) {
      setActiveApp(prev => prev ? ({
        ...prev,
        current_score: newScore,
        critical_count: crit,
        high_count: high,
        medium_count: med,
        low_count: low,
        info_count: info,
      }) : null);
    }

    setApplications(prev =>
      prev.map(app =>
        app.id === targetAppId
          ? {
              ...app,
              current_score: newScore,
              critical_count: crit,
              high_count: high,
              medium_count: med,
              low_count: low,
              info_count: info,
            }
          : app
      )
    );

    return newScore;
  };

  const updateVulnerabilityStatus = (vulnId: string, status: TriageStatus, reason?: string) => {
    const targetVuln = vulnerabilities.find(v => v.id === vulnId);
    const updated = vulnerabilities.map(v => {
      if (v.id === vulnId) {
        return {
          ...v,
          status,
          triage_reason: reason || v.triage_reason,
          triaged_at: new Date().toISOString(),
        };
      }
      return v;
    });

    setVulnerabilities(updated);
    if (targetVuln) {
      const newScore = recalculateSecurityScore(updated, targetVuln.application_id);
      setScoreComparison(prev => ({ before: prev.after, after: newScore }));
      addAuditLog(`VULNERABILITY_${status.toUpperCase()}`, `${targetVuln.title} (${targetVuln.cwe_id})`, status === 'confirmed' ? 'warning' : 'info');
    }
  };

  const formatTargetToAppName = (target: string, scanType: ScanType): string => {
    if (!target || !target.trim()) {
      switch (scanType) {
        case 'web_app': return 'Web Application';
        case 'git_repo': return 'Git Repository';
        case 'api': return 'API Service';
        case 'android_apk': return 'Android Mobile App';
        case 'config_files': return 'Container Infrastructure';
        case 'dependencies': return 'Dependency Manifest';
        default: return 'Source Code Application';
      }
    }
    const clean = target.trim();
    if (clean.startsWith('http://') || clean.startsWith('https://')) {
      try {
        const url = new URL(clean);
        const host = url.hostname.replace(/^www\./, '');
        if (url.pathname && url.pathname !== '/' && (scanType === 'git_repo' || clean.includes('github') || clean.includes('gitlab'))) {
          const parts = url.pathname.replace(/^\//, '').replace(/\.git$/, '').split('/');
          if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
        }
        return host || clean;
      } catch {
        const match = clean.match(/https?:\/\/([^/:]+)/);
        if (match && match[1]) return match[1].replace(/^www\./, '');
      }
    }
    if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(clean)) {
      return clean;
    }
    const fileName = clean.split(/[\\/]/).pop() || clean;
    return fileName.replace(/\.[^/.]+$/, '') || clean;
  };

  const runNewScan = async (
    type: ScanType, 
    target: string, 
    content?: string, 
    appOverrideId?: string
  ): Promise<Scan> => {
    setIsScanning(true);
    setScanProgress(0);
    setTelemetryLogs([]);

    // 1. Resolve Target Application cleanly per URL / target
    const targetAppName = formatTargetToAppName(target, type);
    let targetApp: Application | null = null;

    if (appOverrideId) {
      targetApp = applications.find(a => a.id === appOverrideId) || null;
    }

    // Check if an existing application matches this exact target name or repository/URL
    if (!targetApp) {
      targetApp = applications.find(a => 
        a.name.toLowerCase() === targetAppName.toLowerCase() ||
        (target.startsWith('http') && a.repository_url && (
          a.repository_url.toLowerCase() === target.toLowerCase() ||
          a.repository_url.toLowerCase().includes(targetAppName.toLowerCase())
        ))
      ) || null;
    }

    // If no existing application matches this new target, CREATE A NEW DEDICATED ONE!
    if (!targetApp) {
      const newAppObj: Application = {
        id: `app_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        user_id: userProfile.id,
        name: targetAppName,
        description: `Target application monitored for security posture: ${target}`,
        repository_url: target.startsWith('http') ? target : undefined,
        environment: 'production',
        technology_stack: [],
        current_score: 100,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        last_scanned_at: new Date().toISOString(),
        total_scans: 0,
        created_at: new Date().toISOString(),
      };
      targetApp = newAppObj;
      setApplications(prev => [newAppObj, ...prev]);
      addAuditLog('APPLICATION_REGISTERED', newAppObj.name, 'info');
    }

    const steps = [
      { step: 'Initializing Isolated Security Worker', time: 400, detail: 'Sandboxed isolated scanner environment spun up.' },
      { step: 'Live Endpoint & AST Header Probe', time: 800, detail: 'Inspecting transport TLS, response headers, and DOM structures.' },
      { step: 'Running SAST Vulnerability Rules', time: 1300, detail: 'Scanning for SQLi, XSS, Command Injection, and Auth flaws.' },
      { step: 'Software Composition Analysis (SCA)', time: 1800, detail: 'Cross-referencing package manifests against CVE database.' },
      { step: 'Secret & High-Entropy Key Scraper', time: 2200, detail: 'Checking token structures, cryptographic keys, and environment leaks.' },
      { step: 'AI Security Explainer & Remediation Engine', time: 2600, detail: 'Synthesizing contextual developer fix guidance.' },
      { step: 'Security Report Finalization & Scoring', time: 3000, detail: 'Computing holistic CVSS and OWASP posture score.' },
    ];

    const currentLogs: ScanTelemetryStep[] = [];

    // Probe live endpoint asynchronously during scan initiation
    let liveData: any = null;
    const isLikelyUrl = (type === 'web_app' || type === 'api') && (target.startsWith('http://') || target.startsWith('https://') || target.includes('.'));
    if (isLikelyUrl) {
      try {
        const probeUrl = target.startsWith('http://') || target.startsWith('https://') ? target : `https://${target}`;
        const probeResp = await fetch('/api/scan/inspect-target', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: probeUrl, scanType: type }),
        });
        if (probeResp.ok) {
          const json = await probeResp.json();
          liveData = json.result;
        }
      } catch {
        // Fallback to static engine if probe fails or offline
      }
    }

    for (let i = 0; i < steps.length; i++) {
      const s = steps[i];
      setCurrentStepMessage(s.step);
      setScanProgress(Math.round(((i + 1) / steps.length) * 100));

      currentLogs.push({
        step: s.step,
        status: 'completed',
        timestamp: `00:0${i + 1}.20`,
        detail: s.detail,
      });
      setTelemetryLogs([...currentLogs]);
      await new Promise(r => setTimeout(r, 300));
    }

    const scanId = `scan_${Date.now()}`;
    const scanContent = content || `// Target content\n// ${target}`;
    const analysis = analyzeSecurityContent(scanContent, target, type, scanId, targetApp.id, liveData);

    const newScan: Scan = {
      id: scanId,
      application_id: targetApp.id,
      application_name: targetApp.name,
      scan_type: type,
      target_identifier: target,
      status: 'completed',
      score: analysis.score,
      previous_score: targetApp.current_score,
      score_breakdown: analysis.scoreBreakdown,
      critical_count: analysis.criticalCount,
      high_count: analysis.highCount,
      medium_count: analysis.mediumCount,
      low_count: analysis.lowCount,
      info_count: analysis.infoCount,
      telemetry_logs: currentLogs,
      detected_technologies: analysis.detectedTechnologies,
      vulnerabilities: analysis.vulnerabilities,
      dependencies: analysis.dependencies,
      scanner_version: 'SecureLens Engine v2.4-Core',
      started_at: new Date(Date.now() - 3000).toISOString(),
      completed_at: new Date().toISOString(),
    };

    setVulnerabilities(prev => [...analysis.vulnerabilities, ...prev.filter(v => v.application_id !== targetApp!.id)]);
    if (analysis.dependencies.length > 0) {
      setDependencies(prev => [...analysis.dependencies, ...prev.filter(d => d.application_id !== targetApp!.id)]);
    }
    setActiveScan(newScan);
    setScanHistory(prev => [newScan, ...prev]);

    // Update target application state and switch activeApp to this target
    const updatedApp: Application = {
      ...targetApp,
      previous_score: targetApp.current_score,
      current_score: analysis.score,
      critical_count: analysis.criticalCount,
      high_count: analysis.highCount,
      medium_count: analysis.mediumCount,
      low_count: analysis.lowCount,
      info_count: analysis.infoCount,
      last_scanned_at: new Date().toISOString(),
      total_scans: (targetApp.total_scans || 0) + 1,
      technology_stack: analysis.detectedTechnologies.length > 0 ? analysis.detectedTechnologies : targetApp.technology_stack,
      repository_url: target.startsWith('http') ? target : targetApp.repository_url,
    };

    setActiveApp(updatedApp);
    setApplications(prev => {
      const exists = prev.some(a => a.id === updatedApp.id);
      if (exists) {
        return prev.map(a => a.id === updatedApp.id ? updatedApp : a);
      }
      return [updatedApp, ...prev];
    });

    setScoreComparison({ before: targetApp.current_score, after: analysis.score });
    setIsScanning(false);

    addAuditLog('SECURITY_SCAN_COMPLETED', `${targetApp.name} (Score: ${analysis.score}/100)`, analysis.criticalCount > 0 ? 'critical' : 'info');
    return newScan;
  };

  const sendAIMessage = async (userQuery: string, selectedVulnId?: string) => {
    const userMsg: AIChatMessage = {
      id: `msg_user_${Date.now()}`,
      sender: 'user',
      content: userQuery,
      timestamp: new Date().toISOString(),
      related_vulnerability_id: selectedVulnId,
    };

    setAiMessages(prev => [...prev, userMsg]);
    setIsAiThinking(true);
    await new Promise(r => setTimeout(r, 600));

    const selectedVuln = selectedVulnId 
      ? vulnerabilities.find(v => v.id === selectedVulnId) 
      : vulnerabilities[0];

    const aiRes = generateAIAnswer(userQuery, selectedVuln, vulnerabilities);

    const assistantMsg: AIChatMessage = {
      id: `msg_ai_${Date.now()}`,
      sender: 'assistant',
      content: aiRes.message,
      timestamp: new Date().toISOString(),
      code_snippet: aiRes.codeSnippet,
      suggested_actions: aiRes.suggestedActions,
    };

    setAiMessages(prev => [...prev, assistantMsg]);
    setIsAiThinking(false);
  };

  // Admin User Actions
  const addAdminUser = (userData: Omit<AdminUser, 'id' | 'created_at' | 'last_login'>) => {
    const newUser: AdminUser = {
      ...userData,
      id: `usr_${Date.now()}`,
      last_login: 'Never',
      created_at: new Date().toISOString(),
    };
    setAdminUsers(prev => [...prev, newUser]);
    addAuditLog('USER_INVITED', `${newUser.email} (${newUser.role})`, 'info');
  };

  const updateUserRole = (userId: string, role: AdminUser['role']) => {
    setAdminUsers(prev => prev.map(u => u.id === userId ? { ...u, role } : u));
    addAuditLog('USER_ROLE_UPDATED', `User ${userId} -> ${role}`, 'warning');
  };

  const toggleUserStatus = (userId: string) => {
    setAdminUsers(prev => prev.map(u => {
      if (u.id === userId) {
        const nextStatus = u.status === 'active' ? 'suspended' : 'active';
        addAuditLog('USER_STATUS_TOGGLED', `User ${u.email} -> ${nextStatus}`, 'warning');
        return { ...u, status: nextStatus };
      }
      return u;
    }));
  };

  const deleteUser = (userId: string) => {
    const user = adminUsers.find(u => u.id === userId);
    setAdminUsers(prev => prev.filter(u => u.id !== userId));
    addAuditLog('USER_REMOVED', user?.email || userId, 'warning');
  };

  const toggleScannerRule = (ruleId: string) => {
    setScannerRules(prev => prev.map(r => {
      if (r.id === ruleId) {
        const updated = !r.enabled;
        addAuditLog('SCANNER_RULE_TOGGLED', `${r.name} -> ${updated ? 'ENABLED' : 'DISABLED'}`, 'warning');
        return { ...r, enabled: updated };
      }
      return r;
    }));
  };

  // User Login & Credential Authentication
  const loginUser = (credentials: { 
    email: string; 
    password?: string; 
    fullName?: string; 
    organization?: string; 
    role?: UserProfile['role'] 
  }) => {
    const updatedProfile: UserProfile = {
      id: `usr_${Date.now()}`,
      email: credentials.email,
      full_name: credentials.fullName || credentials.email.split('@')[0],
      organization: credentials.organization || 'Independent Security Lab',
      role: credentials.role || 'owner',
      user_type: 'enterprise',
      created_at: new Date().toISOString(),
    };

    setUserProfile(updatedProfile);
    try {
      localStorage.setItem('securelens_user', JSON.stringify(updatedProfile));
    } catch {
      // ignore storage write errors
    }

    // Also register or update in adminUsers list
    setAdminUsers(prev => {
      const exists = prev.find(u => u.email.toLowerCase() === credentials.email.toLowerCase());
      if (exists) {
        return prev.map(u => u.email.toLowerCase() === credentials.email.toLowerCase()
          ? { ...u, last_login: 'Just now', status: 'active' }
          : u
        );
      }
      return [
        {
          id: updatedProfile.id,
          name: updatedProfile.full_name,
          email: updatedProfile.email,
          role: 'admin',
          status: 'active',
          last_login: 'Just now',
          created_at: new Date().toISOString(),
        },
        ...prev
      ];
    });

    addAuditLog('USER_AUTHENTICATED', `${credentials.email} (Role: ${updatedProfile.role})`, 'info');
  };

  const logoutUser = () => {
    try {
      localStorage.removeItem('securelens_user');
    } catch {
      // ignore
    }
    addAuditLog('USER_LOGOUT', userProfile.email, 'info');
  };

  // Complete Clear / Fresh Start
  const clearAllData = () => {
    setApplications([]);
    setActiveApp(null);
    setVulnerabilities([]);
    setDependencies([]);
    setScanHistory([]);
    setActiveScan(null);
    setScoreComparison({ before: 100, after: 100 });
    localStorage.removeItem('securelens_apps');
    localStorage.removeItem('securelens_scans');
    localStorage.removeItem('securelens_vulns');
    addAuditLog('WORKSPACE_RESET', 'All applications and historical scans wiped to fresh state.', 'critical');
  };

  // Optional Demo Loader for Testing
  const loadDemoData = () => {
    setApplications([DEMO_APPLICATION]);
    setActiveApp(DEMO_APPLICATION);
    setVulnerabilities(INITIAL_VULNERABILITIES);
    setDependencies(INITIAL_DEPENDENCIES);
    setScanHistory(DEMO_SCAN_HISTORY);
    setActiveScan(DEMO_SCAN_HISTORY[0]);
    setScoreComparison({ before: 52, after: 68 });
    addAuditLog('SAMPLE_PROJECT_LOADED', DEMO_APPLICATION.name, 'info');
  };

  const updateUserProfile = (updates: Partial<UserProfile>) => {
    setUserProfile(prev => {
      const updated = { ...prev, ...updates };
      try {
        localStorage.setItem('securelens_user', JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });
    addAuditLog('PROFILE_UPDATED', updates.organization || updates.full_name || 'User Profile', 'info');
  };

  const fixAllIssues = () => {
    if (!activeApp) return;
    const updated = vulnerabilities.map(v => {
      if (v.application_id === activeApp.id) {
        return {
          ...v,
          status: 'fixed' as TriageStatus,
          triage_reason: 'Automated remediation patch applied via developer CI pipeline.',
          triaged_at: new Date().toISOString(),
        };
      }
      return v;
    });

    setVulnerabilities(updated);
    const newScore = 98;
    setActiveApp(prev => prev ? ({
      ...prev,
      previous_score: prev.current_score,
      current_score: newScore,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 1,
    }) : null);

    setApplications(prev => prev.map(a => a.id === activeApp.id ? {
      ...a,
      previous_score: a.current_score,
      current_score: newScore,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 1,
    } : a));

    setScoreComparison({ before: activeApp.current_score, after: newScore });
    addAuditLog('ALL_VULNERABILITIES_FIXED', activeApp.name, 'info');
  };

  return (
    <SecurityContext.Provider
      value={{
        applications,
        activeApp,
        vulnerabilities,
        dependencies,
        scanHistory,
        activeScan,
        setActiveScan,
        isScanning,
        scanProgress,
        currentStepMessage,
        telemetryLogs,
        userProfile,
        aiMessages,
        isAiThinking,
        scoreComparison,
        adminUsers,
        auditLogs,
        scannerRules,
        selectApplication,
        addNewApplication,
        deleteApplication,
        updateVulnerabilityStatus,
        runNewScan,
        sendAIMessage,
        addAuditLog,
        addAdminUser,
        updateUserRole,
        toggleUserStatus,
        deleteUser,
        toggleScannerRule,
        clearAllData,
        loadDemoData,
        fixAllIssues,
        loginUser,
        logoutUser,
        updateUserProfile,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
}

export function useSecurity() {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
}
