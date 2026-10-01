import { NextRequest, NextResponse } from 'next/server';
import { validateTargetUrl } from '@/lib/security/ssrf-protection';
import { analyzeJavaScriptDataFlow, maskSecretValue, checkSqlErrorPatterns } from '@/lib/data-flow-analyzer';
import { buildApplicationArchitecture } from '@/lib/architecture-detector';
import { FalsePositiveEngine } from '@/lib/false-positive-engine';
import { 
  Vulnerability, 
  DiscoveredEndpoint, 
  DiscoveredResource, 
  DetectedTechnology, 
  ApplicationArchitecture 
} from '@/types/security';

export const dynamic = 'force-dynamic';

export interface InspectTargetResponse {
  reachable: boolean;
  statusCode?: number;
  statusText?: string;
  targetUrl: string;
  domain: string;
  path: string;
  scheme: 'https' | 'http';
  pageTitle?: string;
  headers: Record<string, string>;
  missingSecurityHeaders: string[];
  detectedTechnologies: DetectedTechnology[];
  architecture: ApplicationArchitecture;
  endpoints: DiscoveredEndpoint[];
  resources: DiscoveredResource[];
  findings: Vulnerability[];
  falsePositivesSuppressed: number;
  serverInfo?: string;
  poweredBy?: string;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const url = body.url || body.targetUrl || body.target;

    // 1. SSRF Protection & URL Validation
    const ssrfCheck = validateTargetUrl(url, true);
    if (!ssrfCheck.valid || !ssrfCheck.sanitizedUrl) {
      return NextResponse.json({ 
        error: ssrfCheck.error || 'Invalid or forbidden target URL.' 
      }, { status: 400 });
    }

    const validatedUrl = new URL(ssrfCheck.sanitizedUrl);
    const domain = validatedUrl.hostname;
    const path = validatedUrl.pathname + validatedUrl.search;
    const scheme = validatedUrl.protocol.replace(':', '') as 'https' | 'http';

    const scanId = `scan_${Date.now()}`;
    const appId = `app_${domain.replace(/[^a-zA-Z0-9]/g, '_')}`;

    let response: Response | null = null;
    let html = '';
    let isReachable = false;
    let statusCode: number | undefined;
    let statusText: string | undefined;

    // 2. Controlled HTTP Request with 8s Timeout & Safe User-Agent
    try {
      response = await fetch(validatedUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecureLens/3.0-Audit',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Cache-Control': 'no-cache',
        },
        signal: AbortSignal.timeout(8000),
        redirect: 'follow',
      });

      isReachable = true;
      statusCode = response.status;
      statusText = response.statusText;

      const rawText = await response.text();
      // Cap HTML inspection at 2MB to protect scanner resources
      html = rawText.slice(0, 2 * 1024 * 1024);
    } catch {
      isReachable = false;
    }

    const rawHeaders: Record<string, string> = {};
    if (response) {
      response.headers.forEach((val, key) => {
        rawHeaders[key.toLowerCase()] = val;
      });
    }

    // Extract Page Title
    let pageTitle: string | undefined;
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    if (titleMatch && titleMatch[1]) {
      pageTitle = titleMatch[1].trim();
    }

    const candidateFindings: Vulnerability[] = [];
    const missingSecurityHeaders: string[] = [];
    const discoveredEndpoints: DiscoveredEndpoint[] = [];
    const discoveredResources: DiscoveredResource[] = [];
    let falsePositivesSuppressed = 0;

    // Add root endpoint to discovered attack surface
    discoveredEndpoints.push({
      id: `ep_root_${Date.now()}`,
      method: 'GET',
      url: validatedUrl.toString(),
      path: validatedUrl.pathname || '/',
      parameters: Array.from(validatedUrl.searchParams.keys()),
      authRequired: 'Public / None',
      responseStatus: statusCode || 200,
      contentType: rawHeaders['content-type'] || 'text/html',
      source: 'Live Crawl',
      riskIndicator: 'safe',
    });

    // -------------------------------------------------------------
    // MODULE 1: ATTACK SURFACE DISCOVERY (Endpoints, Forms, Links, Scripts)
    // -------------------------------------------------------------
    if (html.length > 0) {
      // Discover Form endpoints
      const formMatches = Array.from(html.matchAll(/<form[^>]*action=["']([^"']*)["'][^>]*method=["']?([a-zA-Z]+)?["']?[^>]*>/gi));
      let formIdx = 1;
      for (const f of formMatches) {
        const action = f[1] || '';
        const method = (f[2] || 'GET').toUpperCase() as any;
        discoveredEndpoints.push({
          id: `ep_form_${formIdx++}`,
          method: method === 'POST' ? 'POST' : 'GET',
          url: action.startsWith('http') ? action : `${validatedUrl.origin}${action.startsWith('/') ? '' : '/'}${action}`,
          path: action || '/',
          parameters: [],
          authRequired: /login|auth|signin|password/i.test(action) ? 'Required' : 'Public / None',
          source: 'Form Action',
          riskIndicator: action.startsWith('http://') ? 'high' : 'safe',
        });
      }

      // Discover API and Route Links
      const linkMatches = Array.from(html.matchAll(/href=["'](\/(?:api|v[0-9]|auth|user|admin|checkout|search)[^"']*)["']/gi));
      let linkIdx = 1;
      for (const l of linkMatches) {
        const linkPath = l[1];
        if (!discoveredEndpoints.some(e => e.path === linkPath)) {
          discoveredEndpoints.push({
            id: `ep_link_${linkIdx++}`,
            method: 'GET',
            url: `${validatedUrl.origin}${linkPath}`,
            path: linkPath,
            parameters: linkPath.includes('?') ? linkPath.split('?')[1].split('&').map(p => p.split('=')[0]) : [],
            authRequired: /admin|user|account/i.test(linkPath) ? 'Required' : 'Public / None',
            source: 'HTML Link',
            riskIndicator: 'safe',
          });
        }
      }
    }

    // -------------------------------------------------------------
    // MODULE 2: PUBLIC METADATA RESOURCES (robots.txt, security.txt, sitemap)
    // -------------------------------------------------------------
    // Robots.txt check
    try {
      const robotsUrl = `${validatedUrl.origin}/robots.txt`;
      const rResp = await fetch(robotsUrl, { method: 'HEAD', signal: AbortSignal.timeout(3000) });
      if (rResp.ok) {
        discoveredResources.push({
          id: 'res_robots',
          type: 'robots.txt',
          path: '/robots.txt',
          status: rResp.status,
          details: 'Public robots.txt file discovered. Used for perimeter route reconnaissance.',
          isVulnerability: false,
        });
      }
    } catch {
      // Ignored
    }

    // Security.txt check (RFC 9116)
    try {
      const secUrl = `${validatedUrl.origin}/.well-known/security.txt`;
      const sResp = await fetch(secUrl, { method: 'HEAD', signal: AbortSignal.timeout(3000) });
      if (sResp.ok) {
        discoveredResources.push({
          id: 'res_security_txt',
          type: 'security.txt',
          path: '/.well-known/security.txt',
          status: sResp.status,
          details: 'RFC 9116 security.txt contact file verified.',
          isVulnerability: false,
        });
      }
    } catch {
      // Ignored
    }

    // -------------------------------------------------------------
    // MODULE 3: SECURITY HEADERS & HSTS & MIME & REFERRER ANALYSIS
    // -------------------------------------------------------------
    // 1. Content-Security-Policy
    const csp = rawHeaders['content-security-policy'] || rawHeaders['x-content-security-policy'];
    if (!csp) {
      missingSecurityHeaders.push('Content-Security-Policy');
      candidateFindings.push({
        id: `vuln_csp_missing_${scanId}`,
        scan_id: scanId,
        application_id: appId,
        title: 'Missing Content-Security-Policy (CSP) Header',
        severity: 'high',
        confidence: 'high',
        category: 'Configuration',
        location: `${domain} (HTTP Response Headers)`,
        evidence: `HTTP ${statusCode || 200} response does not supply a Content-Security-Policy header.`,
        detection_logic: 'Passive inspection of HTTP response headers verified absence of CSP directive.',
        potential_impact: 'Heightened susceptibility to Cross-Site Scripting (XSS), malicious third-party script loads, and clickjacking redressing.',
        why_it_matters: 'Content-Security-Policy restricts script execution and resource loading to cryptographically signed nonces and trusted origins.',
        recommended_fix: 'Define a tailored CSP appropriate for the application resources. Do not use an overly restrictive generic policy that breaks runtime assets.',
        verification_steps: 'Deploy Content-Security-Policy header and inspect browser DevTools console to ensure legitimate scripts load without CSP violation errors.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP', 'https://owasp.org/www-project-secure-headers/'],
        cwe_id: 'CWE-693',
        owasp_category: 'A05:2021-Security Misconfiguration',
        cvss_score: 7.2,
        status: 'confirmed',
        code_language: 'http',
        before_code: `HTTP/1.1 ${statusCode || 200} OK\nContent-Type: ${rawHeaders['content-type'] || 'text/html'}\n// Missing Content-Security-Policy`,
        after_code: `// Express / Helmet: app.use(helmet.contentSecurityPolicy({...}))\n// Next.js (next.config.mjs / middleware.ts):\nContent-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';`,
        created_at: new Date().toISOString(),
        ai_explanation: {
          whatWasFound: 'The server does not send a Content-Security-Policy header in HTTP responses.',
          whySecurityConcern: 'Browsers rely on CSP as defense-in-depth to block unauthorized inline JavaScript and cross-domain data exfiltration.',
          howDetected: 'Direct inspection of the live HTTP response headers.',
          howConfident: 'High confidence. The header was absent from the server response.',
          couldBeFalsePositive: 'No, but static API endpoints or image assets may not require CSP.',
          howToFix: 'In Next.js, add headers in next.config.mjs or middleware.ts. In Express, use the helmet middleware.',
          howToVerify: 'Re-scan with SecureLens or check response headers in curl -I to confirm CSP presence.',
        }
      });
    } else {
      // Evaluate CSP strength
      if (csp.includes("'unsafe-inline'") && !csp.includes("'nonce-") && !csp.includes("'sha256-")) {
        candidateFindings.push({
          id: `vuln_csp_unsafe_inline_${scanId}`,
          scan_id: scanId,
          application_id: appId,
          title: "Permissive CSP Directive: 'unsafe-inline' Without Cryptographic Nonce",
          severity: 'medium',
          confidence: 'high',
          category: 'Configuration',
          location: `${domain} (CSP: script-src)`,
          evidence: `Current CSP: ${csp.slice(0, 120)}...`,
          detection_logic: "Analyzed CSP directives and identified 'unsafe-inline' without accompanying nonce-* or sha256-* restrictions.",
          potential_impact: 'Permits execution of injected inline scripts, weakening XSS defense-in-depth.',
          why_it_matters: 'Removing unsafe-inline stops over 95% of reflected and stored XSS vectors.',
          recommended_fix: "Migrate inline scripts to external bundles or inject per-request cryptographic nonces (e.g. 'nonce-rAnd0m').",
          cwe_id: 'CWE-79',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 6.2,
          status: 'confirmed',
          code_language: 'http',
          before_code: `Content-Security-Policy: ${csp}`,
          after_code: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-\${res.locals.cspNonce}'; object-src 'none';`,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 2. Strict-Transport-Security (HSTS)
    const hsts = rawHeaders['strict-transport-security'];
    if (!hsts && scheme === 'https') {
      missingSecurityHeaders.push('Strict-Transport-Security');
      candidateFindings.push({
        id: `vuln_hsts_missing_${scanId}`,
        scan_id: scanId,
        application_id: appId,
        title: 'Missing Strict-Transport-Security (HSTS) Header',
        severity: 'medium',
        confidence: 'high',
        category: 'Cryptography',
        location: `${domain} (Transport Layer)`,
        evidence: `Endpoint served over HTTPS (${scheme}://) without Strict-Transport-Security header.`,
        detection_logic: 'Inspected response headers on verified HTTPS connection; HSTS was absent.',
        potential_impact: 'Vulnerability to SSL-stripping and Adversary-in-the-Middle (AitM) protocol downgrade attacks on public networks.',
        why_it_matters: 'HSTS instructs compliant browsers to strictly enforce HTTPS and disallow certificate override warnings.',
        recommended_fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains; preload in production web server or CDN.',
        verification_steps: 'Inspect HTTPS response headers using curl -I and verify hstspreload.org compliance.',
        cwe_id: 'CWE-319',
        owasp_category: 'A02:2021-Cryptographic Failures',
        cvss_score: 5.8,
        status: 'potential',
        code_language: 'nginx',
        before_code: `# Insecure configuration without HSTS\nserver {\n    listen 443 ssl;\n    server_name ${domain};\n}`,
        after_code: `# Secure Nginx configuration with HSTS\nserver {\n    listen 443 ssl http2;\n    server_name ${domain};\n    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n}`,
        created_at: new Date().toISOString(),
      });
    } else if (hsts && scheme === 'https') {
      const hasSubdomains = hsts.includes('includeSubDomains');
      const hasPreload = hsts.includes('preload');
      if (!hasSubdomains || !hasPreload) {
        candidateFindings.push({
          id: `vuln_hsts_weak_${scanId}`,
          scan_id: scanId,
          application_id: appId,
          title: 'HSTS Configuration Weakness: Missing includeSubDomains or Preload',
          severity: 'low',
          confidence: 'high',
          category: 'Cryptography',
          location: `${domain} (HSTS: ${hsts})`,
          evidence: `HSTS header detected (${hsts}), but lacks ${!hasSubdomains ? 'includeSubDomains' : ''} ${!hasPreload ? 'preload' : ''}.`,
          detection_logic: 'HSTS directive parser verified header presence but flagged sub-optimal coverage.',
          potential_impact: 'Subdomains remain susceptible to cleartext downgrade attacks.',
          why_it_matters: 'Preloading ensures modern browsers never connect over port 80 even on the first visit.',
          recommended_fix: 'Update header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload and submit to hstspreload.org.',
          cwe_id: 'CWE-319',
          owasp_category: 'A02:2021-Cryptographic Failures',
          cvss_score: 3.5,
          status: 'informational',
          code_language: 'http',
          before_code: `Strict-Transport-Security: ${hsts}`,
          after_code: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 3. MIME Sniffing Protection (X-Content-Type-Options)
    const xcto = rawHeaders['x-content-type-options'];
    if (!xcto || xcto.toLowerCase() !== 'nosniff') {
      missingSecurityHeaders.push('X-Content-Type-Options');
      candidateFindings.push({
        id: `vuln_nosniff_missing_${scanId}`,
        scan_id: scanId,
        application_id: appId,
        title: 'Missing MIME Sniffing Protection (X-Content-Type-Options: nosniff)',
        severity: 'low',
        confidence: 'high',
        category: 'Configuration',
        location: `${domain} (MIME Type Enforcement)`,
        evidence: `Header X-Content-Type-Options was missing or set to "${xcto || 'undefined'}". Actual served Content-Type: "${rawHeaders['content-type'] || 'text/html'}".`,
        detection_logic: 'Header inspection verified absence of nosniff directive.',
        potential_impact: 'Browsers may attempt MIME sniffing on uploaded user files (e.g. text/plain or image/jpeg) and execute them as JavaScript.',
        why_it_matters: 'nosniff forces browsers to strictly honor the declared Content-Type header.',
        recommended_fix: 'Add X-Content-Type-Options: nosniff to all responses in your web server or edge proxy.',
        cwe_id: 'CWE-79',
        owasp_category: 'A05:2021-Security Misconfiguration',
        cvss_score: 3.5,
        status: 'potential',
        code_language: 'http',
        before_code: `HTTP/1.1 200 OK\nContent-Type: ${rawHeaders['content-type'] || 'text/html'}`,
        after_code: `HTTP/1.1 200 OK\nContent-Type: ${rawHeaders['content-type'] || 'text/html'}\nX-Content-Type-Options: nosniff`,
        created_at: new Date().toISOString(),
      });
    }

    // 4. Referrer-Policy
    const referrerPolicy = rawHeaders['referrer-policy'];
    if (!referrerPolicy || referrerPolicy.toLowerCase() === 'unsafe-url') {
      missingSecurityHeaders.push('Referrer-Policy');
      candidateFindings.push({
        id: `vuln_referrer_missing_${scanId}`,
        scan_id: scanId,
        application_id: appId,
        title: 'Missing or Insecure Referrer-Policy Header',
        severity: 'low',
        confidence: 'high',
        category: 'Configuration',
        location: `${domain} (Referrer-Policy)`,
        evidence: `Referrer-Policy is "${referrerPolicy || 'not supplied'}".`,
        detection_logic: 'Header analysis verified absence of modern strict referrer restriction.',
        potential_impact: 'Outgoing link clicks may leak full URLs containing sensitive tokens, session IDs, or private parameters in the Referer header to external destinations.',
        why_it_matters: 'strict-origin-when-cross-origin protects user privacy by only transmitting domain origins across sites.',
        recommended_fix: 'Send Referrer-Policy: strict-origin-when-cross-origin.',
        cwe_id: 'CWE-116',
        owasp_category: 'A05:2021-Security Misconfiguration',
        cvss_score: 3.2,
        status: 'informational',
        code_language: 'http',
        before_code: `// Missing Referrer-Policy`,
        after_code: `Referrer-Policy: strict-origin-when-cross-origin`,
        created_at: new Date().toISOString(),
      });
    }

    // 5. CORS Analysis
    const corsOrigin = rawHeaders['access-control-allow-origin'];
    const corsCreds = rawHeaders['access-control-allow-credentials'];
    if (corsOrigin === '*' && corsCreds === 'true') {
      candidateFindings.push({
        id: `vuln_cors_wildcard_creds_${scanId}`,
        scan_id: scanId,
        application_id: appId,
        title: 'Critical Insecure CORS: Wildcard Origin With Credentials Flag Enabled',
        severity: 'critical',
        confidence: 'high',
        category: 'API Security',
        location: `${domain}${path} (CORS Policy)`,
        evidence: 'Access-Control-Allow-Origin: * coupled with Access-Control-Allow-Credentials: true.',
        detection_logic: 'Correlated CORS response headers and identified invalid, dangerous credential exposure specification.',
        potential_impact: 'Allows malicious third-party websites to extract sensitive authenticated API payloads.',
        why_it_matters: 'Browser security specifications explicitly prohibit credentials with wildcard origins because it completely eliminates cross-origin isolation.',
        recommended_fix: 'Dynamically validate incoming Origin headers against an explicit whitelist and reflect only trusted origins.',
        cwe_id: 'CWE-942',
        owasp_category: 'A01:2021-Broken Access Control',
        cvss_score: 9.1,
        status: 'confirmed',
        code_language: 'javascript',
        before_code: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
        after_code: `const allowedOrigins = ['https://${domain}', 'https://app.${domain}'];\nconst reqOrigin = req.headers.origin;\nif (allowedOrigins.includes(reqOrigin)) {\n  res.setHeader('Access-Control-Allow-Origin', reqOrigin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n  res.setHeader('Vary', 'Origin');\n}`,
        created_at: new Date().toISOString(),
      });
    } else if (corsOrigin === '*') {
      candidateFindings.push({
        id: `vuln_cors_wildcard_${scanId}`,
        scan_id: scanId,
        application_id: appId,
        title: 'Permissive Wildcard Access-Control-Allow-Origin (CORS)',
        severity: 'medium',
        confidence: 'high',
        category: 'API Security',
        location: `${domain}${path} (CORS Policy)`,
        evidence: 'Access-Control-Allow-Origin: * without credentials.',
        detection_logic: 'Observed wildcard CORS header. Evaluated context: public read-only endpoint.',
        potential_impact: 'Permits any external website to read response payloads.',
        why_it_matters: 'APIs containing private tenant data should restrict origins.',
        recommended_fix: 'Restrict CORS Access-Control-Allow-Origin to authorized tenant domains.',
        cwe_id: 'CWE-942',
        owasp_category: 'A05:2021-Security Misconfiguration',
        cvss_score: 5.3,
        status: 'potential',
        code_language: 'http',
        before_code: `Access-Control-Allow-Origin: *`,
        after_code: `Access-Control-Allow-Origin: https://${domain}\nVary: Origin`,
        created_at: new Date().toISOString(),
      });
    }

    // 6. Cookie Security Analysis
    const setCookie = rawHeaders['set-cookie'];
    if (setCookie) {
      const lowerCookie = setCookie.toLowerCase();
      const cookieName = setCookie.split('=')[0] || 'session';
      if (!lowerCookie.includes('httponly')) {
        candidateFindings.push({
          id: `vuln_cookie_httponly_${scanId}`,
          scan_id: scanId,
          application_id: appId,
          title: `Missing HttpOnly Flag on Cookie (${cookieName})`,
          severity: 'high',
          confidence: 'high',
          category: 'Authentication',
          location: `${domain} (Set-Cookie: ${cookieName})`,
          evidence: `Set-Cookie header (${setCookie.split(';')[0]}) lacks HttpOnly attribute.`,
          detection_logic: 'Cookie flag parser verified that client-side JavaScript (document.cookie) can access this token.',
          potential_impact: 'If an XSS bug exists anywhere on this origin, attackers can steal authentication cookies directly.',
          why_it_matters: 'HttpOnly neutralizes session theft from client-side script injection.',
          recommended_fix: 'Add HttpOnly to all session cookies issued by backend servers.',
          cwe_id: 'CWE-1004',
          owasp_category: 'A07:2021-Identification and Authentication Failures',
          cvss_score: 7.1,
          status: 'confirmed',
          code_language: 'http',
          before_code: setCookie,
          after_code: `${setCookie}; HttpOnly; Secure; SameSite=Lax`,
          created_at: new Date().toISOString(),
        });
      }
      if (scheme === 'https' && !lowerCookie.includes('secure')) {
        candidateFindings.push({
          id: `vuln_cookie_secure_${scanId}`,
          scan_id: scanId,
          application_id: appId,
          title: `Missing Secure Attribute on Cookie (${cookieName}) over HTTPS`,
          severity: 'medium',
          confidence: 'high',
          category: 'Cryptography',
          location: `${domain} (Set-Cookie: ${cookieName})`,
          evidence: `Cookie issued over HTTPS without the Secure flag: ${setCookie.split(';')[0]}.`,
          detection_logic: 'Verified HTTPS transmission lacking Secure attribute.',
          potential_impact: 'Browsers may transmit this cookie over cleartext HTTP if a user clicks an unencrypted link.',
          why_it_matters: 'The Secure flag ensures cookies are only transmitted through encrypted TLS tunnels.',
          recommended_fix: 'Append Secure to all cookies issued over HTTPS.',
          cwe_id: 'CWE-614',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 5.5,
          status: 'confirmed',
          code_language: 'http',
          before_code: setCookie,
          after_code: `${setCookie}; Secure; HttpOnly; SameSite=Lax`,
          created_at: new Date().toISOString(),
        });
      }
    }

    // -------------------------------------------------------------
    // MODULE 4: DEEP JAVASCRIPT & DOM XSS DATA-FLOW ANALYSIS
    // -------------------------------------------------------------
    if (html.length > 0) {
      // Extract inline scripts
      const scriptBlocks = Array.from(html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi));
      let sIdx = 1;
      for (const sb of scriptBlocks) {
        const scriptContent = sb[1] || '';
        const dfResult = analyzeJavaScriptDataFlow(
          scriptContent, 
          validatedUrl.toString(), 
          scanId, 
          appId, 
          `Inline <script> Block #${sIdx++}`
        );
        candidateFindings.push(...dfResult.vulnerabilities);
        falsePositivesSuppressed += dfResult.falsePositivesSuppressed;
      }

      // Check Database Error Signatures (Safe non-destructive check)
      const sqlCheck = checkSqlErrorPatterns(html, validatedUrl.pathname);
      if (sqlCheck.detected) {
        candidateFindings.push({
          id: `vuln_sql_error_leak_${scanId}`,
          scan_id: scanId,
          application_id: appId,
          title: `Database Error Pattern & Syntax Trace Disclosed in Response (${sqlCheck.dbType || 'SQL Engine'})`,
          severity: 'high',
          confidence: 'high',
          category: 'Input Security',
          location: `${domain}${path} (Response Body)`,
          evidence: `Signature detected: "${sqlCheck.signature}" indicating active ${sqlCheck.dbType} backend.`,
          detection_logic: 'Identified raw database exception text in public HTTP response body.',
          potential_impact: 'Confirms backend database engine and reveals underlying query structure, aiding SQL injection exploitation.',
          why_it_matters: 'Verbose errors provide attackers with precise syntax requirements for SQL injection.',
          recommended_fix: 'Catch database exceptions globally and return generic opaque error responses (e.g. HTTP 500 with Error ID).',
          cwe_id: 'CWE-209',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 7.5,
          status: 'confirmed',
          code_language: 'javascript',
          before_code: `// Leaking raw DB error\nres.status(500).send(err.message);`,
          after_code: `// Generic sanitized error response\nlogger.error('DB Error', { err, trackingId });\nres.status(500).json({ error: 'Internal Server Error', ref: trackingId });`,
          created_at: new Date().toISOString(),
        });
      }
    }

    // -------------------------------------------------------------
    // MODULE 5: ARCHITECTURE & TECHNOLOGY DETECTION
    // -------------------------------------------------------------
    const { architecture, detectedTechnologies } = buildApplicationArchitecture(
      rawHeaders, 
      html, 
      discoveredEndpoints
    );

    // -------------------------------------------------------------
    // MODULE 6: DEDICATED FALSE POSITIVE ENGINE & CLASSIFICATION
    // -------------------------------------------------------------
    const { classifiedFindings, falsePositiveCount } = FalsePositiveEngine.filterAndClassifyFindings(candidateFindings);
    falsePositivesSuppressed += falsePositiveCount;

    const result: InspectTargetResponse = {
      reachable: isReachable,
      statusCode,
      statusText,
      targetUrl: validatedUrl.toString(),
      domain,
      path,
      scheme,
      pageTitle,
      headers: rawHeaders,
      missingSecurityHeaders,
      detectedTechnologies,
      architecture,
      endpoints: discoveredEndpoints,
      resources: discoveredResources,
      findings: classifiedFindings,
      falsePositivesSuppressed,
      serverInfo: rawHeaders['server'],
      poweredBy: rawHeaders['x-powered-by'],
    };

    return NextResponse.json({ success: true, result });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Inspection failed' }, { status: 500 });
  }
}
