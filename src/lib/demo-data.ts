import { Application, Scan, Vulnerability, DependencyFinding, SecurityMetricProgress } from '@/types/security';

export const DEMO_APPLICATION: Application = {
  id: 'app_banking_api',
  user_id: 'user_dev_01',
  name: 'Apex Banking API & Microservices',
  description: 'Production fintech payment processing gateway and customer balance service.',
  repository_url: 'https://github.com/apex-fintech/banking-core-api',
  environment: 'production',
  technology_stack: [
    { category: 'Backend', name: 'Node.js', version: '18.16.0', confidence: 98 },
    { category: 'Backend', name: 'Express.js', version: '4.18.2', confidence: 95 },
    { category: 'Database', name: 'PostgreSQL', version: '15.2', confidence: 90 },
    { category: 'Language', name: 'TypeScript', version: '5.2', confidence: 99 },
    { category: 'Package Manager', name: 'npm', version: '9.6', confidence: 95 },
  ],
  current_score: 68,
  previous_score: 52,
  critical_count: 2,
  high_count: 3,
  medium_count: 4,
  low_count: 5,
  info_count: 3,
  last_scanned_at: '2026-09-30T18:45:00Z',
  total_scans: 8,
  created_at: '2026-08-15T10:00:00Z',
};

export const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'vuln_1',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    title: 'SQL Injection in Transaction Query Handler',
    severity: 'critical',
    category: 'Input Security',
    location: '/src/controllers/transactionController.ts:line 42',
    line_number: 42,
    description: 'User-controlled query parameter `account_id` is concatenated directly into raw SQL query without parameterization or escaping.',
    potential_impact: 'Unauthorized database read access across all customer balances, arbitrary transaction modification, and potential database takeover.',
    why_it_matters: 'SQL injection allows malicious actors to alter the structure of SQL commands executed by the backend database engine.',
    recommended_fix: 'Use parameterized queries ($1, $2) or an ORM like Prisma/TypeORM instead of dynamic string concatenation.',
    before_code: `// Insecure string concatenation\nconst accountId = req.query.accountId;\nconst sql = "SELECT * FROM transactions WHERE account_id = '" + accountId + "' ORDER BY date DESC";\nconst result = await db.query(sql);`,
    after_code: `// Secure Parameterized Query\nconst accountId = req.query.accountId;\nconst sql = "SELECT id, amount, currency, status, date FROM transactions WHERE account_id = $1 ORDER BY date DESC";\nconst result = await db.query(sql, [accountId]);`,
    code_language: 'typescript',
    cwe_id: 'CWE-89',
    owasp_category: 'A03:2021-Injection',
    cvss_score: 9.8,
    status: 'confirmed',
    created_at: '2026-09-30T18:45:10Z',
  },
  {
    id: 'vuln_2',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    title: 'Exposed Production Stripe Secret Key',
    severity: 'critical',
    category: 'Secrets',
    location: '/config/paymentGateway.ts:line 12',
    line_number: 12,
    description: 'High-entropy secret key detected in source code: sk_live_948f****************',
    potential_impact: 'Attacker can perform unauthorized financial debits, refund manipulation, and access sensitive customer card records.',
    why_it_matters: 'Hardcoded secrets committed to version control remain in commit histories and CI build artifacts.',
    recommended_fix: 'Immediately rotate the exposed key in the Stripe Dashboard. Load credentials exclusively via environment variables and use AWS Secrets Manager.',
    before_code: `// Insecure hardcoded Stripe Secret Key\nexport const stripe = new Stripe("sk_live_948fa918b82ecf94821a99");`,
    after_code: `// Secure environment variable ingestion\nif (!process.env.STRIPE_SECRET_KEY) {\n  throw new Error("STRIPE_SECRET_KEY is required in production environment");\n}\nexport const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);`,
    code_language: 'typescript',
    cwe_id: 'CWE-798',
    owasp_category: 'A07:2021-Identification & Authentication Failures',
    cvss_score: 9.5,
    status: 'confirmed',
    created_at: '2026-09-30T18:45:15Z',
  },
  {
    id: 'vuln_3',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    title: 'Insecure Direct Object Reference (IDOR) on Customer Profile',
    severity: 'high',
    category: 'Authorization',
    location: '/src/routes/userRoutes.ts:line 89',
    line_number: 89,
    description: 'Endpoint `/api/v1/users/:id/kyc` retrieves sensitive identity verification data without verifying if the requesting user matches the requested ID.',
    potential_impact: 'Mass exfiltration of KYC documents, government IDs, and personally identifiable information (PII) by changing the user ID integer in requests.',
    why_it_matters: 'Missing object-level access controls leave user resources accessible to any authenticated platform user.',
    recommended_fix: 'Enforce tenant identity checks matching `req.user.id` against requested resource owner.',
    before_code: `// Insecure: Fetches record directly by request parameter without identity check\nrouter.get('/users/:id/kyc', authenticateUser, async (req, res) => {\n  const kycData = await db.kyc.findByUserId(req.params.id);\n  res.json(kycData);\n});`,
    after_code: `// Secure: Enforces requesting user ownership\nrouter.get('/users/:id/kyc', authenticateUser, async (req, res) => {\n  if (req.user.id !== req.params.id && req.user.role !== 'admin') {\n    return res.status(403).json({ error: 'Access denied: You do not own this record' });\n  }\n  const kycData = await db.kyc.findByUserId(req.params.id);\n  res.json(kycData);\n});`,
    code_language: 'typescript',
    cwe_id: 'CWE-862',
    owasp_category: 'A01:2021-Broken Access Control',
    cvss_score: 8.6,
    status: 'confirmed',
    created_at: '2026-09-30T18:45:20Z',
  },
  {
    id: 'vuln_4',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    title: 'Permissive Wildcard Cross-Origin Resource Sharing (CORS)',
    severity: 'medium',
    category: 'API Security',
    location: '/src/server.ts:line 31',
    line_number: 31,
    description: 'API configuration allows `Access-Control-Allow-Origin: *` while simultaneously supporting authenticated session headers.',
    potential_impact: 'Malicious third-party websites can issue authenticated cross-origin requests on behalf of logged-in banking users.',
    why_it_matters: 'Permissive CORS policies invalidate browser SOP protections.',
    recommended_fix: 'Specify exact allowed production domain origins and disallow wildcard origins when credentials are used.',
    before_code: `// Insecure CORS Wildcard\napp.use(cors({ origin: '*', credentials: true }));`,
    after_code: `// Secure explicit domain whitelist\nconst allowedOrigins = ['https://banking.apexfintech.com', 'https://admin.apexfintech.com'];\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);\n    return callback(new Error('Blocked by CORS security policy'));\n  },\n  credentials: true,\n  methods: ['GET', 'POST', 'PUT', 'DELETE']\n}));`,
    code_language: 'typescript',
    cwe_id: 'CWE-942',
    owasp_category: 'A05:2021-Security Misconfiguration',
    cvss_score: 6.2,
    status: 'confirmed',
    created_at: '2026-09-30T18:45:25Z',
  },
  {
    id: 'vuln_5',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    title: 'Missing Content-Security-Policy & Strict Transport Security Headers',
    severity: 'low',
    category: 'Configuration',
    location: '/src/server.ts:line 19',
    line_number: 19,
    description: 'HTTP response headers do not specify HSTS (HTTP Strict Transport Security), X-Content-Type-Options: nosniff, or CSP directives.',
    potential_impact: 'Subjection to SSL stripping downgrade attacks on insecure Wi-Fi and higher vulnerability to reflected XSS vectors.',
    why_it_matters: 'Defense-in-depth HTTP headers provide standard browser safeguards against common interception and MIME-sniffing tricks.',
    recommended_fix: 'Integrate the Helmet security middleware package to configure secure HTTP response headers.',
    before_code: `const app = express();\n// Missing security headers`,
    after_code: `import helmet from 'helmet';\nconst app = express();\napp.use(helmet({\n  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },\n  contentSecurityPolicy: true\n}));`,
    code_language: 'typescript',
    cwe_id: 'CWE-693',
    owasp_category: 'A05:2021-Security Misconfiguration',
    cvss_score: 3.9,
    status: 'confirmed',
    created_at: '2026-09-30T18:45:30Z',
  },
];

export const INITIAL_DEPENDENCIES: DependencyFinding[] = [
  {
    id: 'dep_1',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    package_name: 'jsonwebtoken',
    installed_version: '8.5.1',
    recommended_version: '9.0.2',
    risk_level: 'high',
    cve_id: 'CVE-2022-23529',
    advisory_summary: 'Remote Code Execution in jwt.verify when processing untrusted key objects.',
    license: 'MIT',
    upgrade_reason: 'Fixes parameter verification flaw that allows unauthenticated code execution.',
    created_at: '2026-09-30T18:45:00Z',
  },
  {
    id: 'dep_2',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    package_name: 'axios',
    installed_version: '0.21.1',
    recommended_version: '1.7.4',
    risk_level: 'high',
    cve_id: 'CVE-2023-45857',
    advisory_summary: 'Server-Side Request Forgery (SSRF) and data leak via cross-domain absolute redirects.',
    license: 'MIT',
    upgrade_reason: 'Patches SSRF token leakage during HTTP 302 redirects.',
    created_at: '2026-09-30T18:45:00Z',
  },
  {
    id: 'dep_3',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    package_name: 'lodash',
    installed_version: '4.17.19',
    recommended_version: '4.17.21',
    risk_level: 'critical',
    cve_id: 'CVE-2020-8203',
    advisory_summary: 'Prototype Pollution leading to potential property injection and Denial of Service.',
    license: 'MIT',
    upgrade_reason: 'Blocks zipObjectDeep and merge prototype mutation vectors.',
    created_at: '2026-09-30T18:45:00Z',
  },
  {
    id: 'dep_4',
    scan_id: 'scan_demo_01',
    application_id: 'app_banking_api',
    package_name: 'express',
    installed_version: '4.18.2',
    recommended_version: '4.19.2',
    risk_level: 'medium',
    cve_id: 'CVE-2024-29041',
    advisory_summary: 'Open Redirect & RegEx DoS vulnerability in routing layer.',
    license: 'MIT',
    upgrade_reason: 'Hardens route matcher against algorithmic complexity attacks.',
    created_at: '2026-09-30T18:45:00Z',
  },
];

export const DEMO_SCAN_HISTORY: Scan[] = [
  {
    id: 'scan_demo_01',
    application_id: 'app_banking_api',
    application_name: 'Apex Banking API & Microservices',
    scan_type: 'git_repo',
    target_identifier: 'branch: main (commit 9f4e2b1)',
    status: 'completed',
    score: 68,
    previous_score: 52,
    score_breakdown: {
      authentication: 74,
      authorization: 65,
      api_security: 70,
      data_protection: 58,
      dependencies: 62,
      configuration: 78,
    },
    critical_count: 2,
    high_count: 3,
    medium_count: 4,
    low_count: 5,
    info_count: 3,
    telemetry_logs: [
      { step: 'Initializing Security Sandbox', status: 'completed', timestamp: '00:00.12' },
      { step: 'Detecting Technology Stack', status: 'completed', timestamp: '00:00.41' },
      { step: 'Parsing AST & Static Analysis', status: 'completed', timestamp: '00:01.05' },
      { step: 'Software Composition Analysis', status: 'completed', timestamp: '00:01.62' },
      { step: 'AI Explainer & Remediation Engine', status: 'completed', timestamp: '00:02.10' },
      { step: 'Generating Audit Report', status: 'completed', timestamp: '00:02.35' },
    ],
    detected_technologies: DEMO_APPLICATION.technology_stack,
    vulnerabilities: INITIAL_VULNERABILITIES,
    dependencies: INITIAL_DEPENDENCIES,
    scanner_version: 'SecureLens Engine v2.4-Core',
    started_at: '2026-09-30T18:42:00Z',
    completed_at: '2026-09-30T18:45:00Z',
  },
  {
    id: 'scan_demo_00',
    application_id: 'app_banking_api',
    application_name: 'Apex Banking API & Microservices',
    scan_type: 'source_code',
    target_identifier: 'branch: release-1.2.0',
    status: 'completed',
    score: 52,
    score_breakdown: {
      authentication: 55,
      authorization: 50,
      api_security: 60,
      data_protection: 45,
      dependencies: 50,
      configuration: 65,
    },
    critical_count: 4,
    high_count: 6,
    medium_count: 5,
    low_count: 8,
    info_count: 4,
    telemetry_logs: [],
    detected_technologies: DEMO_APPLICATION.technology_stack,
    vulnerabilities: [],
    dependencies: [],
    scanner_version: 'SecureLens Engine v2.3-Core',
    started_at: '2026-09-15T12:00:00Z',
    completed_at: '2026-09-15T12:04:00Z',
  },
];

export const SECURITY_PROGRESS_HISTORY: SecurityMetricProgress[] = [
  { date: 'Aug 15', score: 48, critical: 5, high: 7, medium: 9, low: 12, fixed_issues: 0 },
  { date: 'Aug 29', score: 54, critical: 4, high: 6, medium: 8, low: 10, fixed_issues: 4 },
  { date: 'Sep 12', score: 61, critical: 3, high: 5, medium: 6, low: 8, fixed_issues: 9 },
  { date: 'Sep 24', score: 65, critical: 2, high: 4, medium: 5, low: 6, fixed_issues: 14 },
  { date: 'Sep 30', score: 68, critical: 2, high: 3, medium: 4, low: 5, fixed_issues: 18 },
];

export const SAMPLE_VULNERABLE_CODE_SNIPPETS = {
  express_api: `import express from 'express';
import { Pool } from 'pg';
import Stripe from 'stripe';

const app = express();
const db = new Pool({ connectionString: 'postgres://user:pass@localhost:5432/bank' });

// 1. Hardcoded Stripe Live Secret Key
const stripe = new Stripe("sk_live_948fa918b82ecf94821a99");

// 2. Wildcard CORS Configuration
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "*");
  next();
});

// 3. SQL Injection in balance query
app.get('/api/v1/accounts/balance', async (req, res) => {
  const accountId = req.query.accountId;
  const query = "SELECT balance, currency FROM accounts WHERE id = '" + accountId + "'";
  const result = await db.query(query);
  res.json(result.rows);
});

// 4. Broken Access Control / IDOR
app.get('/api/v1/transfers/:id', async (req, res) => {
  const transfer = await db.query("SELECT * FROM transfers WHERE id = $1", [req.params.id]);
  res.json(transfer.rows[0]);
});

app.listen(4000);`,

  python_flask: `from flask import Flask, request, jsonify
import sqlite3
import hashlib

app = Flask(__name__)

# Hardcoded API Secret
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

@app.route("/search_records")
def search():
    user_input = request.args.get('term')
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection risk
    query = "SELECT * FROM users WHERE username = '%s'" % user_input
    cursor.execute(query)
    return jsonify(cursor.fetchall())

@app.route("/hash_password", methods=["POST"])
def hash_pwd():
    password = request.json.get('password')
    # Weak MD5 hashing algorithm
    h = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"hash": h})`,

  react_frontend: `import React, { useState } from 'react';

export default function UserComment({ commentData }) {
  // Reflected Cross-Site Scripting (XSS) risk via dangerouslySetInnerHTML
  return (
    <div className="comment-box">
      <h4>{commentData.author}</h4>
      <div dangerouslySetInnerHTML={{ __html: commentData.rawBody }} />
    </div>
  );
}`
};
