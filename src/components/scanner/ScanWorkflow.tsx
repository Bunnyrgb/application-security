'use client';

import React, { useState } from 'react';
import { 
  Code2, 
  GitBranch, 
  FileArchive, 
  Smartphone, 
  Globe, 
  Cpu, 
  FileJson, 
  Boxes,
  Play,
  Upload,
  AlertCircle,
  FileCheck,
  Sparkles,
  Trash2,
  Sliders,
  ShieldCheck
} from 'lucide-react';
import { ScanType } from '@/types/security';
import { SAMPLE_VULNERABLE_CODE_SNIPPETS } from '@/lib/demo-data';

interface ScanWorkflowProps {
  onStartScan: (type: ScanType, target: string, content?: string) => void;
  isScanning: boolean;
}

export default function ScanWorkflow({ onStartScan, isScanning }: ScanWorkflowProps) {
  const [selectedType, setSelectedType] = useState<ScanType>('web_app');

  // Input states - starting clean without dummy pre-filled values
  const [webUrl, setWebUrl] = useState('');
  const [crawlDepth, setCrawlDepth] = useState<'quick' | 'standard' | 'deep'>('standard');

  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('main');
  const [authToken, setAuthToken] = useState('');

  const [apiUrl, setApiUrl] = useState('');
  const [apiSpec, setApiSpec] = useState('');

  const [codeContent, setCodeContent] = useState('');
  const [codeLanguage, setCodeLanguage] = useState('typescript');

  const [configContent, setConfigContent] = useState('');
  const [configFilename, setConfigFilename] = useState('Dockerfile');

  const [depsContent, setDepsContent] = useState('');
  const [depsFilename, setDepsFilename] = useState('package.json');

  const [apkPackage, setApkPackage] = useState('');
  const [apkContent, setApkContent] = useState('');

  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [zipContent, setZipContent] = useState<string>('');

  const scanTypes = [
    {
      id: 'web_app' as ScanType,
      name: 'Web Application',
      icon: Globe,
      desc: 'Live edge URL inspection, SSL/TLS, CORS policies, and HTTP security headers.',
      detects: 'CSP, HSTS, CORS wildcard, Cookie flags, Server banners'
    },
    {
      id: 'git_repo' as ScanType,
      name: 'Git Repository',
      icon: GitBranch,
      desc: 'Connect GitHub or GitLab public & private repos for deep branch audits.',
      detects: 'Unprotected branches, CI/CD gates, leaked .env in history'
    },
    {
      id: 'api' as ScanType,
      name: 'API (REST / GraphQL)',
      icon: Cpu,
      desc: 'Audit OpenAPI / Swagger specifications and live API endpoints.',
      detects: 'OWASP API Top 10, BOLA, Lack of Rate Limiting, Data exposure'
    },
    {
      id: 'source_code' as ScanType,
      name: 'Source Code (SAST)',
      icon: Code2,
      desc: 'Analyze single files or multi-language code snippets with AST AST parser.',
      detects: 'SQLi, XSS, Command Injection, Insecure Crypto, Hardcoded Keys'
    },
    {
      id: 'dependencies' as ScanType,
      name: 'Dependencies (SCA)',
      icon: Boxes,
      desc: 'Audit package.json, requirements.txt, pom.xml against CVE databases.',
      detects: 'Known NVD/OSV CVEs, vulnerable versions, license compliance'
    },
    {
      id: 'config_files' as ScanType,
      name: 'Container & Docker',
      icon: FileJson,
      desc: 'Audit Dockerfile, Kubernetes YAMLs, and cloud manifests.',
      detects: 'Root container user, unpinned tags, exposed daemon ports'
    },
    {
      id: 'android_apk' as ScanType,
      name: 'Android Mobile App',
      icon: Smartphone,
      desc: 'Mobile application binary analysis and Android manifest security auditing.',
      detects: 'Cleartext traffic, exported components, debuggable flags'
    },
    {
      id: 'zip_upload' as ScanType,
      name: 'ZIP Codebase Archive',
      icon: FileArchive,
      desc: 'Upload a compressed codebase archive up to 250MB securely.',
      detects: 'Full application directory structure, configs, dependencies'
    },
  ];

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.size > 250 * 1024 * 1024) {
        alert('File exceeds 250MB limit. Please upload a smaller archive.');
        return;
      }
      setUploadedFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setZipContent((event.target?.result as string) || '');
      };
      reader.readAsText(file.slice(0, 100000));
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    switch (selectedType) {
      case 'web_app': {
        const target = webUrl.trim() || 'https://mywebsite.com';
        onStartScan('web_app', target, undefined);
        break;
      }
      case 'git_repo': {
        const repo = gitUrl.trim() || 'organization/repository';
        const target = `${repo} (${gitBranch || 'main'})`;
        onStartScan('git_repo', target, undefined);
        break;
      }
      case 'api': {
        const target = apiUrl.trim() || 'https://api.domain.com/v1';
        onStartScan('api', target, apiSpec || undefined);
        break;
      }
      case 'source_code': {
        const filename = `Application.${codeLanguage === 'python' ? 'py' : codeLanguage === 'go' ? 'go' : 'ts'}`;
        const content = codeContent.trim() || '// Clean application source code\nconsole.log("Ready");';
        onStartScan('source_code', filename, content);
        break;
      }
      case 'config_files': {
        const target = configFilename || 'Dockerfile';
        const content = configContent.trim() || 'FROM node:18-alpine\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "index.js"]';
        onStartScan('config_files', target, content);
        break;
      }
      case 'dependencies': {
        const target = depsFilename || 'package.json';
        const content = depsContent.trim() || '{\n  "name": "my-app",\n  "dependencies": {\n    "express": "^4.19.2"\n  }\n}';
        onStartScan('dependencies', target, content);
        break;
      }
      case 'android_apk': {
        const target = apkPackage.trim() || 'com.example.secureapp';
        const content = apkContent.trim() || '<manifest package="com.example.secureapp">\n  <application android:usesCleartextTraffic="false" />\n</manifest>';
        onStartScan('android_apk', target, content);
        break;
      }
      case 'zip_upload': {
        const target = uploadedFileName || 'application-source.zip';
        onStartScan('zip_upload', target, zipContent || undefined);
        break;
      }
      default:
        onStartScan(selectedType, 'Custom Target', codeContent);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Scan Type Selection Grid */}
      <div>
        <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block mb-3 font-semibold">
          1. Select Security Engine Target Type
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {scanTypes.map((type) => {
            const Icon = type.icon;
            const isSelected = selectedType === type.id;

            return (
              <button
                key={type.id}
                type="button"
                onClick={() => setSelectedType(type.id)}
                className={`p-3.5 rounded-xl border text-left transition-all ${
                  isSelected
                    ? 'bg-indigo-600/15 border-cyan-400 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-400/50'
                    : 'bg-[#0b101c] border-slate-800/80 hover:border-slate-700 hover:bg-[#0e1424]'
                }`}
              >
                <div className="flex items-center gap-2.5 mb-2">
                  <div className={`p-2 rounded-lg ${isSelected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-semibold text-slate-200">
                    {type.name}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2 mb-2">
                  {type.desc}
                </p>
                <div className="text-[10px] font-mono text-cyan-300/80 bg-cyan-950/30 p-1 rounded border border-cyan-800/30 truncate">
                  Detects: {type.detects}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 2. Target Configuration Form */}
      <form onSubmit={handleSubmit} className="p-5 rounded-xl border border-slate-800 bg-[#0a0e1a] space-y-4">
        <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block font-semibold">
          2. Target Application Parameters
        </label>

        {/* Web Application Mode */}
        {selectedType === 'web_app' && (
          <div className="space-y-4">
            <div>
              <label className="text-[11px] font-mono text-slate-300 block mb-1">
                Target Website URL / Hostname *
              </label>
              <input
                type="text"
                required
                value={webUrl}
                onChange={(e) => setWebUrl(e.target.value)}
                placeholder="https://yourwebsite.com or https://app.company.org"
                className="w-full px-3 py-2 text-xs font-mono bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
              />
              <p className="text-[10px] text-slate-400 mt-1">
                SecureLens will run live edge probes checking Content-Security-Policy, HSTS, CORS wildcard permissions, and server signature disclosures.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">
                  Analysis Depth
                </label>
                <select
                  value={crawlDepth}
                  onChange={(e) => setCrawlDepth(e.target.value as any)}
                  className="w-full px-3 py-2 text-xs font-mono bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="quick">Quick Probe (Edge Headers & SSL/TLS Only)</option>
                  <option value="standard">Standard Web Posture (Headers + Technology Stack)</option>
                  <option value="deep">Comprehensive (Full Edge Surface + Subdomain Heuristics)</option>
                </select>
              </div>

              <div className="flex items-center gap-2 p-3 rounded-lg bg-[#060912] border border-slate-800/80">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-[11px] text-slate-300">
                  Non-invasive passive scan. No aggressive fuzzing or Denial of Service traffic.
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Git Repository Mode */}
        {selectedType === 'git_repo' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="md:col-span-2">
                <label className="text-[11px] font-mono text-slate-300 block mb-1">
                  Repository URL (GitHub / GitLab / Bitbucket) *
                </label>
                <input
                  type="text"
                  required
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
                  placeholder="https://github.com/organization/repository"
                />
              </div>
              <div>
                <label className="text-[11px] font-mono text-slate-300 block mb-1">
                  Branch / Ref
                </label>
                <input
                  type="text"
                  value={gitBranch}
                  onChange={(e) => setGitBranch(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  placeholder="main"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                Personal Access Token (Optional - only required for private repositories)
              </label>
              <input
                type="password"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
                placeholder="ghp_************************************"
              />
              <p className="text-[10px] text-slate-500 mt-1">
                Tokens are held ephemerally in memory during repository inspection and never written to disk.
              </p>
            </div>
          </div>
        )}

        {/* API Mode */}
        {selectedType === 'api' && (
          <div className="space-y-4">
            <div>
              <label className="text-[11px] font-mono text-slate-300 block mb-1">
                API Base Endpoint URL *
              </label>
              <input
                type="text"
                required
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
                placeholder="https://api.yourdomain.com/v1"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                OpenAPI / Swagger Spec or Endpoints List (Optional JSON / YAML)
              </label>
              <textarea
                value={apiSpec}
                onChange={(e) => setApiSpec(e.target.value)}
                rows={5}
                className="w-full p-3 font-mono text-xs bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
                placeholder='// Paste OpenAPI specification or endpoints:&#10;GET /api/v1/users&#10;POST /api/v1/orders'
              />
            </div>
          </div>
        )}

        {/* Source Code Mode */}
        {selectedType === 'source_code' && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-300 font-mono">Language:</span>
                <select
                  value={codeLanguage}
                  onChange={(e) => setCodeLanguage(e.target.value)}
                  className="px-2.5 py-1 text-xs font-mono bg-[#060912] border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="typescript">TypeScript / Node.js</option>
                  <option value="javascript">JavaScript</option>
                  <option value="python">Python</option>
                  <option value="go">Go (Golang)</option>
                  <option value="java">Java</option>
                  <option value="php">PHP</option>
                </select>
              </div>

              {/* Quick load scenarios */}
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setCodeContent(SAMPLE_VULNERABLE_CODE_SNIPPETS.express_api)}
                  className="px-2 py-1 text-[11px] font-mono rounded bg-slate-800/80 text-cyan-300 hover:text-white hover:bg-slate-700 transition-colors"
                >
                  Load SQLi Demo
                </button>
                <button
                  type="button"
                  onClick={() => setCodeContent(SAMPLE_VULNERABLE_CODE_SNIPPETS.python_flask)}
                  className="px-2 py-1 text-[11px] font-mono rounded bg-slate-800/80 text-cyan-300 hover:text-white hover:bg-slate-700 transition-colors"
                >
                  Load Python Demo
                </button>
                <button
                  type="button"
                  onClick={() => setCodeContent(SAMPLE_VULNERABLE_CODE_SNIPPETS.react_frontend)}
                  className="px-2 py-1 text-[11px] font-mono rounded bg-slate-800/80 text-cyan-300 hover:text-white hover:bg-slate-700 transition-colors"
                >
                  Load XSS Demo
                </button>
                {codeContent && (
                  <button
                    type="button"
                    onClick={() => setCodeContent('')}
                    className="p-1 text-slate-400 hover:text-rose-400 transition-colors"
                    title="Clear editor"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            <textarea
              value={codeContent}
              onChange={(e) => setCodeContent(e.target.value)}
              rows={10}
              className="w-full p-4 font-mono text-xs bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 leading-relaxed placeholder-slate-600"
              placeholder="// Paste your application source code here..."
            />
          </div>
        )}

        {/* Configuration & Docker Mode */}
        {selectedType === 'config_files' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <label className="text-[11px] font-mono text-slate-300">File Type:</label>
                <input
                  type="text"
                  value={configFilename}
                  onChange={(e) => setConfigFilename(e.target.value)}
                  className="px-2.5 py-1 text-xs font-mono bg-[#060912] border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 w-36"
                  placeholder="Dockerfile"
                />
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setConfigContent('FROM node:latest\nWORKDIR /app\nCOPY . .\nENV DB_PASSWORD=prodSuperSecret99\nEXPOSE 22 80\nCMD ["node", "server.js"]')}
                  className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-800 text-cyan-300 hover:text-white"
                >
                  Load Vulnerable Dockerfile
                </button>
                {configContent && (
                  <button
                    type="button"
                    onClick={() => setConfigContent('')}
                    className="p-1 text-slate-400 hover:text-rose-400"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            <textarea
              value={configContent}
              onChange={(e) => setConfigContent(e.target.value)}
              rows={9}
              className="w-full p-4 font-mono text-xs bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 leading-relaxed placeholder-slate-600"
              placeholder="FROM node:18-alpine&#10;WORKDIR /app&#10;COPY package*.json ./&#10;RUN npm install&#10;COPY . .&#10;USER node&#10;CMD ['node', 'server.js']"
            />
          </div>
        )}

        {/* Dependencies (SCA) Mode */}
        {selectedType === 'dependencies' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <label className="text-[11px] font-mono text-slate-300">Manifest:</label>
                <input
                  type="text"
                  value={depsFilename}
                  onChange={(e) => setDepsFilename(e.target.value)}
                  className="px-2.5 py-1 text-xs font-mono bg-[#060912] border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 w-36"
                  placeholder="package.json"
                />
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setDepsContent('{\n  "name": "ecommerce-service",\n  "version": "1.0.0",\n  "dependencies": {\n    "lodash": "4.17.15",\n    "axios": "0.21.1",\n    "jsonwebtoken": "8.5.1",\n    "express": "4.18.2"\n  }\n}')}
                  className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-800 text-cyan-300 hover:text-white"
                >
                  Load Sample package.json
                </button>
                {depsContent && (
                  <button
                    type="button"
                    onClick={() => setDepsContent('')}
                    className="p-1 text-slate-400 hover:text-rose-400"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            <textarea
              value={depsContent}
              onChange={(e) => setDepsContent(e.target.value)}
              rows={9}
              className="w-full p-4 font-mono text-xs bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 leading-relaxed placeholder-slate-600"
              placeholder='{\n  "dependencies": {\n    "your-library": "1.0.0"\n  }\n}'
            />
          </div>
        )}

        {/* Android APK Mode */}
        {selectedType === 'android_apk' && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[11px] font-mono text-slate-300 block mb-1">
                  Android Package Name *
                </label>
                <input
                  type="text"
                  value={apkPackage}
                  onChange={(e) => setApkPackage(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
                  placeholder="com.company.paymentapp"
                />
              </div>

              <div className="flex items-end">
                <button
                  type="button"
                  onClick={() => {
                    setApkPackage('com.bank.mobile');
                    setApkContent('<manifest package="com.bank.mobile">\n  <application android:usesCleartextTraffic="true">\n    <activity android:name=".PaymentActivity" android:exported="true" />\n  </application>\n</manifest>');
                  }}
                  className="px-3 py-2 text-xs font-mono rounded bg-slate-800 text-cyan-300 hover:text-white w-full text-center"
                >
                  Load Sample Manifest (Cleartext & Exported)
                </button>
              </div>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                AndroidManifest.xml Snippet (Optional)
              </label>
              <textarea
                value={apkContent}
                onChange={(e) => setApkContent(e.target.value)}
                rows={6}
                className="w-full p-4 font-mono text-xs bg-[#060912] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 leading-relaxed placeholder-slate-600"
                placeholder='<manifest package="com.example.app">&#10;  <application android:usesCleartextTraffic="false" />&#10;</manifest>'
              />
            </div>
          </div>
        )}

        {/* ZIP Upload Mode */}
        {selectedType === 'zip_upload' && (
          <div className="border-2 border-dashed border-slate-800 rounded-xl p-8 text-center hover:border-cyan-500/50 transition-colors bg-[#080c16]">
            <Upload className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
            <div className="text-xs text-slate-200 font-medium">
              Drag & Drop your project ZIP archive or click to browse
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Supports .zip, .tar.gz up to 250MB. Code is extracted into an ephemeral, non-executing sandbox.
            </p>
            <input
              type="file"
              accept=".zip,.tar,.gz,.tgz"
              onChange={handleFileUpload}
              className="hidden"
              id="zip-upload-input"
            />
            <label
              htmlFor="zip-upload-input"
              className="mt-4 inline-block px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 text-slate-200 hover:text-white cursor-pointer"
            >
              Browse Local Archive
            </label>
            {uploadedFileName && (
              <div className="mt-3 text-xs text-emerald-400 font-mono flex items-center justify-center gap-1.5">
                <FileCheck className="w-4 h-4" />
                Selected: {uploadedFileName}
              </div>
            )}
          </div>
        )}

        {/* Security Sandboxing Assurance */}
        <div className="p-3 rounded-lg bg-indigo-950/20 border border-indigo-900/30 flex items-start gap-2.5 text-xs text-slate-300">
          <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <p className="text-[11px] leading-relaxed">
            <strong className="text-cyan-300">Zero Execution Guarantee:</strong> SecureLens executes analysis purely via Abstract Syntax Tree (AST) token parsing, static pattern matching, and dependency graph auditing. Uploaded code is never run, and sandbox storage is wiped following completion.
          </p>
        </div>

        {/* Submit Button */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={isScanning}
            className="flex items-center gap-2 px-6 py-2.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-indigo-600 via-cyan-600 to-indigo-600 hover:opacity-90 shadow-lg shadow-indigo-600/30 transition-all font-mono disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-white" />
            <span>{isScanning ? 'Security Scan Running...' : 'Execute Security Scan'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
