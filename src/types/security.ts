export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type VulnerabilityCategory = 
  | 'Authentication'
  | 'Authorization'
  | 'Input Security'
  | 'API Security'
  | 'Secrets'
  | 'Cryptography'
  | 'Configuration'
  | 'Dependencies'
  | 'Infrastructure';

export type TriageStatus = 'confirmed' | 'false_positive' | 'accepted_risk' | 'fixed';

export type ScanType = 
  | 'source_code'
  | 'git_repo'
  | 'zip_upload'
  | 'android_apk'
  | 'web_app'
  | 'api'
  | 'config_files'
  | 'dependencies';

export type ScanStatus = 'queued' | 'initializing' | 'scanning' | 'analyzing_ai' | 'completed' | 'failed';

export interface ScoreBreakdown {
  authentication: number;
  authorization: number;
  api_security: number;
  data_protection: number;
  dependencies: number;
  configuration: number;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  application_id: string;
  title: string;
  severity: SeverityLevel;
  category: VulnerabilityCategory;
  description: string;
  location: string;
  line_number?: number;
  potential_impact: string;
  why_it_matters: string;
  recommended_fix: string;
  before_code?: string;
  after_code?: string;
  code_language: string;
  cwe_id: string;
  owasp_category: string;
  cvss_score: number;
  status: TriageStatus;
  triage_reason?: string;
  triaged_at?: string;
  created_at: string;
}

export interface DependencyFinding {
  id: string;
  scan_id: string;
  application_id: string;
  package_name: string;
  installed_version: string;
  recommended_version: string;
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  cve_id?: string;
  advisory_summary: string;
  license: string;
  upgrade_reason: string;
  created_at: string;
}

export interface ScanTelemetryStep {
  step: string;
  status: 'pending' | 'in_progress' | 'completed' | 'warning' | 'error';
  timestamp: string;
  detail?: string;
}

export interface Scan {
  id: string;
  application_id: string;
  application_name: string;
  scan_type: ScanType;
  target_identifier: string;
  status: ScanStatus;
  score: number;
  previous_score?: number;
  score_breakdown: ScoreBreakdown;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  telemetry_logs: ScanTelemetryStep[];
  detected_technologies: DetectedTechnology[];
  vulnerabilities: Vulnerability[];
  dependencies: DependencyFinding[];
  scanner_version: string;
  error_message?: string;
  started_at: string;
  completed_at?: string;
}

export interface DetectedTechnology {
  category: 'Frontend' | 'Backend' | 'Database' | 'Language' | 'DevOps' | 'Package Manager';
  name: string;
  version?: string;
  icon?: string;
  confidence: number;
}

export interface Application {
  id: string;
  user_id: string;
  name: string;
  description: string;
  repository_url?: string;
  environment: 'production' | 'staging' | 'development';
  technology_stack: DetectedTechnology[];
  current_score: number;
  previous_score?: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  last_scanned_at: string;
  total_scans: number;
  created_at: string;
}

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  organization: string;
  role: 'owner' | 'security_analyst' | 'developer' | 'viewer';
  user_type: 'developer' | 'student' | 'enterprise';
  avatar_url?: string;
  created_at: string;
}

export interface AIChatMessage {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  related_vulnerability_id?: string;
  code_snippet?: {
    language: string;
    code: string;
    type: 'before' | 'after' | 'example';
  };
  suggested_actions?: string[];
}

export interface SecurityMetricProgress {
  date: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixed_issues: number;
}

export interface AuditLog {
  id: string;
  user_email: string;
  action: string;
  target: string;
  ip_address: string;
  timestamp: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface ScannerRuleConfig {
  id: string;
  name: string;
  category: VulnerabilityCategory;
  enabled: boolean;
  severity: SeverityLevel;
  description: string;
}
