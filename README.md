# SecureLens — AI-Powered Application Security Platform

> **"See the Risk. Fix the Risk."**  
> *Find vulnerabilities before attackers do.*

SecureLens is a modern, startup-grade application security analysis and posture management (ASPM) platform designed for developers, engineering teams, and cybersecurity analysts. It combines static application security testing (SAST), software composition analysis (SCA), secret detection, and context-aware AI remediation.

---

## 🚀 Key Features

### 1. Multi-Mode Security Scanning
* **Source Code Analysis**: Direct syntax tree and regex heuristic analysis with instant vulnerability identification.
* **Git Repository Auditing**: Connect GitHub / GitLab repositories (branches, commits, and tags) with token authentication.
* **ZIP / Tarball Archive Uploads**: Isolated, non-executing sandbox unpacking up to 250MB.
* **API Security & OpenAPI Audits**: Detect BOLA/IDOR, permissive CORS wildcards, and unauthenticated endpoints.
* **Configuration & Infrastructure Auditing**: Dockerfile security, Kubernetes manifests, and HTTP security headers.
* **Software Composition Analysis (SCA)**: Real-time CVE lookups for npm, PyPI, and Maven dependencies.

### 2. Comprehensive Vulnerability Detection
* **Input Security**: SQL Injection (CWE-89), Cross-Site Scripting (CWE-79), Command Injection (CWE-78).
* **Secrets Hunter**: Automated detection and masking (`sk_live_****************`) of Stripe keys, AWS credentials, JWT secrets, and private keys.
* **Authorization & Access Control**: Insecure Direct Object References (IDOR / CWE-862), missing role checks.
* **Authentication**: Insecure JWT signature verification (CWE-287), algorithm confusion (`none`), missing token expirations.
* **Cryptography**: Deprecated hashing algorithms (MD5 / SHA-1 / CWE-328), pseudo-random token generation (`Math.random`).
* **Security Misconfigurations**: Missing HSTS, Content-Security-Policy (CSP), and permissive CORS origins (CWE-942).

### 3. Developer-Friendly Remediation & Before/After Code Diffs
Every finding contains:
* Severity (Critical, High, Medium, Low, Informational) + CVSS v3.1 Score
* Exact File Location and Line Number
* Potential Impact and Business Risk explanation
* Side-by-side **Before (Vulnerable)** vs **After (Remediated)** code comparison across TypeScript, Node.js, Python, Java, and React
* Triage status workflow: Confirmed, False Positive, Accepted Risk, Fixed

### 4. Contextual SecureLens AI Assistant
An interactive conversational security advisor grounded strictly in active AST findings:
* *"Why is this vulnerability dangerous?"*
* *"How can I fix this?"*
* *"Show me a secure implementation in TypeScript/Python."*
* *"Explain this in simple English to my team."*
* *"Which issues should I fix first?"*

### 5. Executive PDF Audit Reports
* Full printable and exportable cybersecurity audit report with Executive Summary, Scorecard, OWASP/CWE compliance breakdown, and remediation checklist.

---

## 🏗️ Architecture & Technology Stack

* **Frontend**: Next.js 14 (App Router), React 18, TypeScript
* **Styling**: Tailwind CSS, Cyberpunk Glassmorphic Dark Design System
* **Icons**: Lucide Icons & Phosphor Icons
* **Database & Auth**: Supabase PostgreSQL with complete Row Level Security (RLS) policies
* **Security Sandbox**: Isolated non-execution AST parsing architecture

---

## 🛠️ Getting Started

### Prerequisites
* Node.js v18+ or v20+
* npm or yarn

### Installation

1. Clone or navigate to the project directory:
   ```bash
   cd "c:\Users\koppu\OneDrive\Pictures\Desktop\application security"
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables (Optional):
   ```bash
   cp .env.example .env.local
   ```

4. Launch the local development server:
   ```bash
   npm run dev
   ```

5. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

---

## 🗄️ Database Setup (Supabase PostgreSQL)

To initialize the database in Supabase:
1. Navigate to your Supabase project dashboard.
2. Open the **SQL Editor**.
3. Copy the contents of [`supabase_schema.sql`](./supabase_schema.sql) and execute the script.
4. Tables created with Row Level Security (RLS):
   * `profiles`
   * `applications`
   * `scans`
   * `vulnerabilities`
   * `dependencies`
   * `team_members`
   * `audit_logs`

---

## 📄 License
This project is licensed under the MIT License.
