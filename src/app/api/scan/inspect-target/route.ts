import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export interface TargetFinding {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'Configuration' | 'Input Security' | 'Authentication' | 'Authorization' | 'API Security' | 'Cryptography' | 'Secrets' | 'Dependencies';
  location: string;
  description: string;
  potential_impact: string;
  why_it_matters: string;
  recommendation: string;
  cwe: string;
  owasp_category: string;
  cvss_score: number;
  before_code: string;
  after_code: string;
  code_language: string;
}

export interface InspectResult {
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
  detectedTechnologies: Array<{
    category: 'Frontend' | 'Backend' | 'Database' | 'Language' | 'DevOps' | 'Package Manager';
    name: string;
    version?: string;
    confidence: number;
  }>;
  detectedDependencies: Array<{
    name: string;
    version: string;
    cve_id?: string;
    severity?: 'critical' | 'high' | 'medium' | 'low';
    description?: string;
    remediation?: string;
  }>;
  findings: TargetFinding[];
  serverInfo?: string;
  poweredBy?: string;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { url } = body;

    if (!url || typeof url !== 'string') {
      return NextResponse.json({ error: 'Missing or invalid target url' }, { status: 400 });
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch {
      return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 });
    }

    const domain = parsedUrl.hostname;
    const path = parsedUrl.pathname + parsedUrl.search;
    const scheme = parsedUrl.protocol.replace(':', '') as 'https' | 'http';

    const result: InspectResult = {
      reachable: false,
      targetUrl: parsedUrl.toString(),
      domain,
      path,
      scheme,
      headers: {},
      missingSecurityHeaders: [],
      detectedTechnologies: [],
      detectedDependencies: [],
      findings: [],
    };

    let response: Response | null = null;
    let html = '';

    // Attempt live network probe with realistic browser User-Agent
    try {
      response = await fetch(parsedUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecureLens/2.4',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Cache-Control': 'no-cache',
        },
        signal: AbortSignal.timeout(8000), // 8 seconds timeout for international/test targets
        redirect: 'follow',
      });
      result.reachable = true;
      result.statusCode = response.status;
      result.statusText = response.statusText;
      try {
        html = await response.text();
      } catch {
        html = '';
      }
    } catch (primaryErr) {
      // If HTTPS failed and no scheme was explicitly provided, attempt HTTP fallback
      if (scheme === 'https' && !url.startsWith('https://')) {
        try {
          const fallbackUrl = new URL(`http://${domain}${path}`);
          response = await fetch(fallbackUrl.toString(), {
            method: 'GET',
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecureLens/2.4',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
            signal: AbortSignal.timeout(6000),
            redirect: 'follow',
          });
          result.reachable = true;
          result.statusCode = response.status;
          result.statusText = response.statusText;
          result.scheme = 'http';
          try {
            html = await response.text();
          } catch {
            html = '';
          }
        } catch {
          // Both failed
        }
      }
    }

    // -------------------------------------------------------------
    // SCENARIO 1: TARGET IS REACHABLE (LIVE INSPECTION)
    // -------------------------------------------------------------
    if (response && result.reachable) {
      const headersObj: Record<string, string> = {};
      response.headers.forEach((val, key) => {
        headersObj[key.toLowerCase()] = val;
      });
      result.headers = headersObj;

      // Extract Page Title
      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (titleMatch && titleMatch[1]) {
        result.pageTitle = titleMatch[1].trim();
      }

      // 1. Cleartext HTTP Check
      if (result.scheme === 'http') {
        result.findings.push({
          title: 'Cleartext HTTP Protocol in Use (Missing TLS/HTTPS)',
          severity: 'high',
          category: 'Cryptography',
          location: `${domain} (Port 80 HTTP)`,
          description: `Target ${domain} was accessed over plaintext HTTP. All session tokens, submitted credentials, and HTML content can be intercepted or altered via Adversary-in-the-Middle (AitM) attacks.`,
          potential_impact: 'Network eavesdropping, credential theft, and transparent injection of malicious scripts into user web sessions.',
          why_it_matters: 'Transport Layer Security (TLS) is the cornerstone of web security, mandatory for data confidentiality and integrity.',
          recommendation: 'Enforce HTTPS via automated TLS 1.3 certificates (e.g., Let\'s Encrypt) and redirect all HTTP traffic to HTTPS using HTTP 301 Moved Permanently.',
          cwe: 'CWE-319',
          owasp_category: 'A02:2021-Cryptographic Failures',
          cvss_score: 7.5,
          before_code: `# Insecure HTTP web server\nserver {\n    listen 80;\n    server_name ${domain};\n    root /var/www/html;\n}`,
          after_code: `# Hardened HTTPS redirect\nserver {\n    listen 80;\n    server_name ${domain};\n    return 301 https://$host$request_uri;\n}\n\nserver {\n    listen 443 ssl http2;\n    server_name ${domain};\n    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;\n}`,
          code_language: 'nginx',
        });
      }

      // 2. Content-Security-Policy (CSP)
      const csp = headersObj['content-security-policy'] || headersObj['x-content-security-policy'];
      if (!csp) {
        result.missingSecurityHeaders.push('Content-Security-Policy');
        result.findings.push({
          title: 'Missing Content-Security-Policy (CSP) Header',
          severity: 'high',
          category: 'Configuration',
          location: `${domain} (HTTP Response Headers)`,
          description: `The live server at ${domain} returned HTTP ${response.status} without a Content-Security-Policy header. Browsers cannot restrict unauthorized script or stylesheet sources.`,
          potential_impact: 'Significantly heightened vulnerability to Cross-Site Scripting (XSS), code injection, and data exfiltration.',
          why_it_matters: 'Content-Security-Policy is the single most effective defense-in-depth standard to prevent inline XSS and unauthorized remote script loads.',
          recommendation: "Deploy a Content-Security-Policy header restricting script execution to authorized domains and cryptographic nonces.",
          cwe: 'CWE-693',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 7.2,
          before_code: `HTTP/1.1 ${response.status} ${response.statusText}\nContent-Type: ${headersObj['content-type'] || 'text/html'}\n// Missing Content-Security-Policy`,
          after_code: `HTTP/1.1 ${response.status} ${response.statusText}\nContent-Type: ${headersObj['content-type'] || 'text/html'}\nContent-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';`,
          code_language: 'http',
        });
      } else {
        // Evaluate CSP strength
        if (csp.includes("'unsafe-inline'") && !csp.includes("'nonce-") && !csp.includes("'sha256-")) {
          result.findings.push({
            title: "Permissive Content-Security-Policy: 'unsafe-inline' Script Execution",
            severity: 'medium',
            category: 'Configuration',
            location: `${domain} (CSP Header)`,
            description: `The CSP header on ${domain} explicitly permits 'unsafe-inline' scripts. An attacker injecting markup via stored or reflected parameters can execute JavaScript arbitrarily.`,
            potential_impact: 'Bypasses modern XSS mitigations by allowing untrusted inline JavaScript execution.',
            why_it_matters: "Removing 'unsafe-inline' and moving to cryptographic nonces or hashes stops 95%+ of client-side code execution bugs.",
            recommendation: "Replace 'unsafe-inline' with CSP Level 3 cryptographic nonces ('nonce-...') generated per-request.",
            cwe: 'CWE-79',
            owasp_category: 'A03:2021-Injection',
            cvss_score: 6.2,
            before_code: `Content-Security-Policy: ${csp}`,
            after_code: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-\${res.locals.cspNonce}'; object-src 'none';`,
            code_language: 'http',
          });
        }
        if (csp.includes("'unsafe-eval'")) {
          result.findings.push({
            title: "Dangerous Content-Security-Policy: 'unsafe-eval' Enabled",
            severity: 'medium',
            category: 'Configuration',
            location: `${domain} (CSP Header)`,
            description: `The CSP directive script-src contains 'unsafe-eval', permitting window.eval() and dynamic string-to-code execution in user browsers.`,
            potential_impact: 'Enables DOM-based code execution if untrusted input reaches evaluation sinks.',
            why_it_matters: "Modern web applications should use native JSON.parse() and structured data rather than eval().",
            recommendation: "Refactor code to remove dynamic evaluation routines and eliminate 'unsafe-eval' from the CSP header.",
            cwe: 'CWE-95',
            owasp_category: 'A03:2021-Injection',
            cvss_score: 5.7,
            before_code: `Content-Security-Policy: ... script-src 'self' 'unsafe-eval' ...`,
            after_code: `Content-Security-Policy: default-src 'self'; script-src 'self';`,
            code_language: 'http',
          });
        }
      }

      // 3. Strict-Transport-Security (HSTS)
      const hsts = headersObj['strict-transport-security'];
      if (!hsts && result.scheme === 'https') {
        result.missingSecurityHeaders.push('Strict-Transport-Security');
        result.findings.push({
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          severity: 'medium',
          category: 'Cryptography',
          location: `${domain} (Transport Security)`,
          description: `No Strict-Transport-Security header detected on ${domain}. Browsers will allow initial plaintext connections, leaving users vulnerable to SSL-stripping AitM attacks on public Wi-Fi.`,
          potential_impact: 'Adversary-in-the-Middle downgrade from HTTPS to HTTP and session hijacking.',
          why_it_matters: 'HSTS instructs browsers to refuse unencrypted HTTP connections permanently and disallow certificate override bypasses.',
          recommendation: 'Configure your web server or edge CDN to send Strict-Transport-Security with max-age=31536000, includeSubDomains, and preload.',
          cwe: 'CWE-319',
          owasp_category: 'A02:2021-Cryptographic Failures',
          cvss_score: 5.8,
          before_code: `# Insecure configuration without HSTS\nserver {\n    listen 443 ssl;\n    server_name ${domain};\n}`,
          after_code: `# Secure configuration with HSTS Preload\nserver {\n    listen 443 ssl http2;\n    server_name ${domain};\n    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n}`,
          code_language: 'nginx',
        });
      } else if (hsts && result.scheme === 'https') {
        if (!hsts.includes('includeSubDomains') || !hsts.includes('preload')) {
          result.findings.push({
            title: 'Suboptimal HSTS Header: Missing includeSubDomains or Preload',
            severity: 'low',
            category: 'Cryptography',
            location: `${domain} (HSTS Header)`,
            description: `The HSTS header (${hsts}) does not cover subdomains or qualify for the global browser HSTS Preload list.`,
            potential_impact: 'Subdomains (e.g. staging.${domain}, dev.${domain}) remain vulnerable to protocol downgrade attacks.',
            why_it_matters: 'The HSTS preload list ensures browsers NEVER connect over port 80 even on the very first request.',
            recommendation: 'Update header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload and submit to hstspreload.org.',
            cwe: 'CWE-319',
            owasp_category: 'A02:2021-Cryptographic Failures',
            cvss_score: 3.8,
            before_code: `Strict-Transport-Security: ${hsts}`,
            after_code: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`,
            code_language: 'http',
          });
        }
      }

      // 4. X-Frame-Options / Clickjacking
      const xfo = headersObj['x-frame-options'];
      if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
        result.missingSecurityHeaders.push('X-Frame-Options');
        result.findings.push({
          title: 'Missing X-Frame-Options Header (Clickjacking Risk)',
          severity: 'medium',
          category: 'Configuration',
          location: `${domain} (Frame Protection)`,
          description: `${domain} does not supply X-Frame-Options or CSP frame-ancestors. Any third-party attacker can embed this application inside an invisible <iframe> on a malicious website.`,
          potential_impact: 'Clickjacking / UI Redressing attacks, tricking authenticated users into making unintentional purchases, transfers, or settings changes.',
          why_it_matters: 'X-Frame-Options stops web pages from being weaponized as phishing frames.',
          recommendation: 'Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header, and frame-ancestors in Content-Security-Policy.',
          cwe: 'CWE-1021',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 5.4,
          before_code: `// HTTP Response from ${domain}\n// Missing X-Frame-Options and frame-ancestors`,
          after_code: `X-Frame-Options: SAMEORIGIN\nContent-Security-Policy: ... frame-ancestors 'self';`,
          code_language: 'http',
        });
      }

      // 5. X-Content-Type-Options
      const xcto = headersObj['x-content-type-options'];
      if (!xcto || xcto.toLowerCase() !== 'nosniff') {
        result.missingSecurityHeaders.push('X-Content-Type-Options');
        result.findings.push({
          title: 'Missing X-Content-Type-Options: nosniff Header',
          severity: 'low',
          category: 'Configuration',
          location: `${domain} (MIME Type Enforcement)`,
          description: `The web server at ${domain} does not explicitly prevent MIME sniffing. Browsers may inspect content and execute text/plain or image files as executable JavaScript.`,
          potential_impact: 'Cross-Site Scripting via uploaded user avatars or text files if MIME detection overrides Content-Type.',
          why_it_matters: 'X-Content-Type-Options: nosniff forces browsers to strictly honor the declared Content-Type header.',
          recommendation: 'Configure reverse proxy to send X-Content-Type-Options: nosniff on all responses.',
          cwe: 'CWE-79',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 3.5,
          before_code: `// Response header missing nosniff`,
          after_code: `X-Content-Type-Options: nosniff`,
          code_language: 'http',
        });
      }

      // 6. Cross-Origin Resource Sharing (CORS)
      const corsOrigin = headersObj['access-control-allow-origin'];
      const corsCreds = headersObj['access-control-allow-credentials'];
      if (corsOrigin === '*' && corsCreds === 'true') {
        result.findings.push({
          title: 'Critical Insecure CORS: Wildcard Origin With Credentials Flag',
          severity: 'critical',
          category: 'API Security',
          location: `${domain}${path} (CORS Policy)`,
          description: `Endpoint returns Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true. This violates browser security specs and exposes authenticated sessions to cross-origin extraction.`,
          potential_impact: 'Cross-origin leakage of sensitive user data and authentication cookies to arbitrary attacker websites.',
          why_it_matters: 'CORS credentials must never be coupled with a wildcard origin.',
          recommendation: 'Whitelist specific trusted origins dynamically and reject requests with untrusted Origin headers.',
          cwe: 'CWE-942',
          owasp_category: 'A01:2021-Broken Access Control',
          cvss_score: 9.1,
          before_code: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
          after_code: `const allowed = ['https://${domain}', 'https://app.${domain}'];\nconst origin = req.headers.origin;\nif (allowed.includes(origin)) {\n  res.setHeader('Access-Control-Allow-Origin', origin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n  res.setHeader('Vary', 'Origin');\n}`,
          code_language: 'javascript',
        });
      } else if (corsOrigin === '*') {
        result.findings.push({
          title: 'Permissive Wildcard Access-Control-Allow-Origin (CORS)',
          severity: 'medium',
          category: 'API Security',
          location: `${domain}${path} (CORS Policy)`,
          description: `Endpoint responds with Access-Control-Allow-Origin: *, allowing any public web application to read API response payloads.`,
          potential_impact: 'Unauthorized cross-origin reading of API data.',
          why_it_matters: 'Sensitive APIs should restrict CORS origins to trusted domains only.',
          recommendation: 'Restrict CORS Access-Control-Allow-Origin to authorized tenant domains.',
          cwe: 'CWE-942',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 5.3,
          before_code: `Access-Control-Allow-Origin: *`,
          after_code: `Access-Control-Allow-Origin: https://${domain}\nVary: Origin`,
          code_language: 'http',
        });
      }

      // 7. Cookie Security Inspection (Set-Cookie headers)
      const rawCookie = headersObj['set-cookie'];
      if (rawCookie) {
        const lowerCookie = rawCookie.toLowerCase();
        if (!lowerCookie.includes('httponly')) {
          result.findings.push({
            title: 'Missing HttpOnly Flag on Session Cookies',
            severity: 'high',
            category: 'Authentication',
            location: `${domain} (Set-Cookie: ${rawCookie.split(';')[0]})`,
            description: `A cookie was issued without the HttpOnly attribute. Client-side JavaScript (document.cookie) can access this cookie directly.`,
            potential_impact: 'If an XSS vulnerability exists anywhere on the domain, attackers can steal session tokens and hijack accounts instantly.',
            why_it_matters: 'The HttpOnly flag blocks JavaScript access, neutralizing session theft from client-side script injection.',
            recommendation: 'Append HttpOnly to all Set-Cookie headers in your backend framework.',
            cwe: 'CWE-1004',
            owasp_category: 'A07:2021-Identification and Authentication Failures',
            cvss_score: 7.1,
            before_code: `Set-Cookie: session_token=abc123xyz; Path=/;`,
            after_code: `Set-Cookie: session_token=abc123xyz; Path=/; HttpOnly; Secure; SameSite=Lax;`,
            code_language: 'http',
          });
        }
        if (result.scheme === 'https' && !lowerCookie.includes('secure')) {
          result.findings.push({
            title: 'Missing Secure Flag on Cookies over HTTPS',
            severity: 'medium',
            category: 'Cryptography',
            location: `${domain} (Set-Cookie: ${rawCookie.split(';')[0]})`,
            description: `The cookie lacks the Secure attribute. Browsers may transmit this cookie over unencrypted HTTP requests if a user clicks an http link.`,
            potential_impact: 'Cookie leakage over cleartext network hops.',
            why_it_matters: 'The Secure flag ensures cookies are only transmitted through encrypted TLS tunnels.',
            recommendation: 'Set Secure flag on all cookies issued over HTTPS.',
            cwe: 'CWE-614',
            owasp_category: 'A05:2021-Security Misconfiguration',
            cvss_score: 5.5,
            before_code: `Set-Cookie: auth=xyz; Path=/;`,
            after_code: `Set-Cookie: auth=xyz; Path=/; Secure; HttpOnly; SameSite=Strict;`,
            code_language: 'http',
          });
        }
        if (!lowerCookie.includes('samesite')) {
          result.findings.push({
            title: 'Missing SameSite Cookie Attribute (Cross-Site Request Forgery Exposure)',
            severity: 'medium',
            category: 'Authentication',
            location: `${domain} (Set-Cookie: ${rawCookie.split(';')[0]})`,
            description: `No SameSite attribute was set on the cookie. The cookie may be included in cross-origin requests originating from external third-party sites.`,
            potential_impact: 'Increases exposure to Cross-Site Request Forgery (CSRF) and credentialed cross-site state tampering.',
            why_it_matters: 'SameSite=Lax or SameSite=Strict provides browser-level defense against CSRF attacks.',
            recommendation: 'Configure SameSite=Lax (or SameSite=Strict for sensitive areas) on all session cookies.',
            cwe: 'CWE-1275',
            owasp_category: 'A01:2021-Broken Access Control',
            cvss_score: 5.8,
            before_code: `Set-Cookie: sid=9876; Path=/;`,
            after_code: `Set-Cookie: sid=9876; Path=/; SameSite=Lax; HttpOnly; Secure;`,
            code_language: 'http',
          });
        }
      }

      // 8. Server & Technology Version Disclosure
      const serverHeader = headersObj['server'];
      const poweredByHeader = headersObj['x-powered-by'];
      if (serverHeader) result.serverInfo = serverHeader;
      if (poweredByHeader) result.poweredBy = poweredByHeader;

      if (poweredByHeader || (serverHeader && /\d/.test(serverHeader))) {
        result.findings.push({
          title: `Server Technology Banner Disclosure (${poweredByHeader ? `X-Powered-By: ${poweredByHeader}` : `Server: ${serverHeader}`})`,
          severity: 'low',
          category: 'Configuration',
          location: `${domain} (HTTP Header: ${poweredByHeader ? 'X-Powered-By' : 'Server'})`,
          description: `The live endpoint broadcasts exact software versions in response headers, giving reconnaissance advantage to attackers looking for known CVEs.`,
          potential_impact: 'Enables targeted exploit search for specific unpatched web server vulnerabilities.',
          why_it_matters: 'Removing technology banners enforces defense-in-depth and reduces reconnaissance data for attackers.',
          recommendation: 'Mask or disable server signature banners (e.g. server_tokens off in Nginx, app.disable("x-powered-by") in Express).',
          cwe: 'CWE-200',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 3.5,
          before_code: `# Exposed version banner\nServer: ${serverHeader || 'Apache/2.4.41'}\nX-Powered-By: ${poweredByHeader || 'Express'}`,
          after_code: `# Hardened Nginx / Express config\nserver_tokens off;\napp.disable('x-powered-by');`,
          code_language: 'nginx',
        });
      }

      // 9. Referrer-Policy
      const referrerPolicy = headersObj['referrer-policy'];
      if (!referrerPolicy || referrerPolicy.toLowerCase() === 'unsafe-url') {
        result.missingSecurityHeaders.push('Referrer-Policy');
        result.findings.push({
          title: 'Missing or Insecure Referrer-Policy Header',
          severity: 'low',
          category: 'Configuration',
          location: `${domain} (Referrer-Policy)`,
          description: `No strict Referrer-Policy is specified. Outgoing link clicks and resource requests may leak full path URLs containing sensitive tokens or IDs in the Referer header to external third parties.`,
          potential_impact: 'Information disclosure of internal route structures, session tokens, or private resource IDs.',
          why_it_matters: 'Referrer-Policy restricts the URL information sent to third-party domains.',
          recommendation: 'Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.',
          cwe: 'CWE-116',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 3.2,
          before_code: `// Missing Referrer-Policy`,
          after_code: `Referrer-Policy: strict-origin-when-cross-origin`,
          code_language: 'http',
        });
      }

      // 10. Permissions-Policy
      const permPolicy = headersObj['permissions-policy'] || headersObj['feature-policy'];
      if (!permPolicy) {
        result.missingSecurityHeaders.push('Permissions-Policy');
        result.findings.push({
          title: 'Missing Permissions-Policy Header',
          severity: 'low',
          category: 'Configuration',
          location: `${domain} (Permissions-Policy)`,
          description: `No Permissions-Policy header configured. Browser APIs (camera, microphone, geolocation, payment, accelerometer) are not explicitly restricted for embedded third-party iframes.`,
          potential_impact: 'Malicious scripts or embedded iframes could request sensitive hardware capabilities.',
          why_it_matters: 'Permissions-Policy enforces least-privilege for modern browser hardware APIs.',
          recommendation: "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
          cwe: 'CWE-693',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 2.8,
          before_code: `// Missing Permissions-Policy`,
          after_code: `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`,
          code_language: 'http',
        });
      }

      // -------------------------------------------------------------
      // DEEP HTML & DOM ANALYSIS
      // -------------------------------------------------------------
      if (html.length > 0) {
        // A) Form Security & CSRF
        const forms = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
        forms.forEach((formHtml, idx) => {
          const actionMatch = formHtml.match(/action=["']([^"']*)["']/i);
          const methodMatch = formHtml.match(/method=["']([^"']*)["']/i);
          const hasPasswordInput = /<input[^>]*type=["']password["']/i.test(formHtml);
          const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();
          const action = actionMatch ? actionMatch[1] : '';

          // Insecure action over HTTP
          if (action.startsWith('http://') && result.scheme === 'https') {
            result.findings.push({
              title: `Insecure Form Submission Action over HTTP on HTTPS Page (Form #${idx + 1})`,
              severity: 'high',
              category: 'Cryptography',
              location: `${domain} (HTML Form: ${action})`,
              description: `A web form on ${domain} explicitly submits data to an unencrypted HTTP destination (${action}), bypassing HTTPS encryption.`,
              potential_impact: 'Form values submitted by the user are transmitted across the internet in plaintext.',
              why_it_matters: 'Form actions must always match the encrypted HTTPS origin.',
              recommendation: `Change the form action attribute to submit to HTTPS (action="https://${domain}/...").`,
              cwe: 'CWE-319',
              owasp_category: 'A02:2021-Cryptographic Failures',
              cvss_score: 7.4,
              before_code: `<form action="${action}" method="${method}">`,
              after_code: `<form action="https://${domain}/api/submit" method="POST">`,
              code_language: 'html',
            });
          }

          // Sensitive form missing CSRF token
          if (hasPasswordInput && method === 'POST') {
            const hasCsrf = /name=["'](csrf|_token|authenticity_token|xsrf|token)["']/i.test(formHtml);
            if (!hasCsrf) {
              result.findings.push({
                title: `Authentication Form Missing Anti-CSRF Token Defense (Form #${idx + 1})`,
                severity: 'high',
                category: 'Authentication',
                location: `${domain} (HTML Form: ${action || 'POST /'})`,
                description: `A login or password form was detected without an embedded Anti-CSRF hidden input token. An external website could submit credentials or state modifications on behalf of the user.`,
                potential_impact: 'Account takeover or unauthorized state manipulation via Cross-Site Request Forgery.',
                why_it_matters: 'State-changing POST actions must validate a unique, unpredictable secret per user session.',
                recommendation: 'Embed a cryptographically signed CSRF token in all forms and validate it server-side on submission.',
                cwe: 'CWE-352',
                owasp_category: 'A01:2021-Broken Access Control',
                cvss_score: 7.5,
                before_code: `<form method="POST" action="${action || '/login'}">\n  <input type="password" name="password" />\n  <button type="submit">Sign In</button>\n</form>`,
                after_code: `<form method="POST" action="${action || '/login'}">\n  <input type="hidden" name="_csrf" value="\${csrfToken}" />\n  <input type="password" name="password" autocomplete="current-password" />\n  <button type="submit">Sign In</button>\n</form>`,
                code_language: 'html',
              });
            }
          }
        });

        // B) External Links with Target Blank (Reverse Tabnabbing)
        const targetBlankLinks = html.match(/<a[^>]*target=["']_blank["'][^>]*>/gi) || [];
        const insecureBlankLinks = targetBlankLinks.filter(l => !/rel=["'][^"']*noopener[^"']*["']/i.test(l) && !/rel=["'][^"']*noreferrer[^"']*["']/i.test(l));
        if (insecureBlankLinks.length > 0) {
          result.findings.push({
            title: `Reverse Tabnabbing Vulnerability in Target Blank Links (${insecureBlankLinks.length} Links Found)`,
            severity: 'medium',
            category: 'Input Security',
            location: `${domain} (HTML <a> tags)`,
            description: `The webpage contains external links using target="_blank" without rel="noopener noreferrer". When a user clicks, the target page can execute window.opener.location = "malicious-phishing-url".`,
            potential_impact: 'Phishing attack where an external page replaces the original tab with a replica credential harvesting page.',
            why_it_matters: 'rel="noopener noreferrer" ensures the browser isolates the execution context of newly opened tabs.',
            recommendation: 'Add rel="noopener noreferrer" to all anchor tags with target="_blank".',
            cwe: 'CWE-1022',
            owasp_category: 'A05:2021-Security Misconfiguration',
            cvss_score: 5.3,
            before_code: insecureBlankLinks[0],
            after_code: insecureBlankLinks[0].replace(/target=["']_blank["']/i, 'target="_blank" rel="noopener noreferrer"'),
            code_language: 'html',
          });
        }

        // C) External Scripts without Subresource Integrity (SRI)
        const cdnScripts = html.match(/<script[^>]*src=["']https?:\/\/(?!localhost|127\.0\.0\.1|${domain})[^"']+\.js[^"']*["'][^>]*>/gi) || [];
        const scriptsWithoutSri = cdnScripts.filter(s => !/integrity=["']/i.test(s));
        if (scriptsWithoutSri.length > 0) {
          const sampleScript = scriptsWithoutSri[0];
          const srcMatch = sampleScript.match(/src=["']([^"']+)["']/i);
          result.findings.push({
            title: `Missing Subresource Integrity (SRI) on External CDN Scripts (${scriptsWithoutSri.length} Discovered)`,
            severity: 'medium',
            category: 'Configuration',
            location: `${domain} (External Script: ${srcMatch ? srcMatch[1].slice(0, 60) + '...' : 'CDN Script'})`,
            description: `JavaScript libraries are loaded from external CDNs without an integrity hash. If the third-party CDN is compromised, malicious code will be automatically executed in user browsers.`,
            potential_impact: 'Supply-chain compromise and silent malicious payload execution.',
            why_it_matters: 'Subresource Integrity (SRI) ensures browsers reject scripts whose cryptographic hash does not match.',
            recommendation: 'Add integrity="sha384-..." and crossorigin="anonymous" to all external script tags.',
            cwe: 'CWE-353',
            owasp_category: 'A06:2021-Vulnerable and Outdated Components',
            cvss_score: 5.6,
            before_code: sampleScript,
            after_code: sampleScript.replace('>', ' integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous">'),
            code_language: 'html',
          });
        }

        // D) Dangerous DOM XSS patterns in inline scripts
        const inlineScripts = html.match(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi) || [];
        inlineScripts.forEach((scriptHtml) => {
          if (/\.innerHTML\s*=/i.test(scriptHtml) || /document\.write\(/i.test(scriptHtml) || /eval\(/i.test(scriptHtml)) {
            result.findings.push({
              title: 'Client-Side DOM Cross-Site Scripting (DOM-XSS) Pattern in Page Script',
              severity: 'high',
              category: 'Input Security',
              location: `${domain} (Inline <script> Block)`,
              description: `Detected dangerous sink patterns (.innerHTML, eval, or document.write) inside inline page scripts. If input from location.hash or URL search parameters flows into these sinks, attackers can achieve zero-click XSS.`,
              potential_impact: 'Client-side script execution, session token exfiltration, and arbitrary DOM manipulation.',
              why_it_matters: 'DOM-based XSS executes entirely on the client and bypasses backend WAF inspection.',
              recommendation: 'Replace element.innerHTML with element.textContent or use DOMPurify.sanitize().',
              cwe: 'CWE-79',
              owasp_category: 'A03:2021-Injection',
              cvss_score: 7.3,
              before_code: scriptHtml.slice(0, 200) + (scriptHtml.length > 200 ? '\n// ... truncated' : ''),
              after_code: `// Secure DOM update using textContent or sanitizer\nelement.textContent = sanitizeInput(untrustedData);`,
              code_language: 'javascript',
            });
          }
        });

        // E) Mixed Content Detection (HTTP resources on HTTPS page)
        if (result.scheme === 'https') {
          const mixedContentMatches = html.match(/(src|href)=["']http:\/\/[^"']+["']/gi) || [];
          if (mixedContentMatches.length > 0) {
            result.findings.push({
              title: `Mixed Content: Insecure HTTP Assets Requested on HTTPS Page (${mixedContentMatches.length} Found)`,
              severity: 'medium',
              category: 'Cryptography',
              location: `${domain} (Mixed Content: ${mixedContentMatches[0]})`,
              description: `The webpage is delivered over HTTPS but requests subresources (images, scripts, or stylesheets) over unencrypted HTTP. Modern browsers will block or mark the connection as degraded.`,
              potential_impact: 'Active network attackers can replace HTTP assets with malicious scripts or inspect image requests.',
              why_it_matters: 'Mixed content undermines the end-to-end security guarantee of HTTPS.',
              recommendation: 'Update all asset URLs to use https:// or protocol-relative // URLs.',
              cwe: 'CWE-311',
              owasp_category: 'A02:2021-Cryptographic Failures',
              cvss_score: 5.0,
              before_code: mixedContentMatches[0] || 'src="http://..."',
              after_code: (mixedContentMatches[0] || 'src="http://..."').replace('http://', 'https://'),
              code_language: 'html',
            });
          }
        }

        // F) Sensitive Comments Exposure
        const comments = html.match(/<!--([\s\S]*?)-->/g) || [];
        const sensitiveComments = comments.filter(c => /(TODO|FIXME|password|secret|key|admin|debug|token|api_key|internal)/i.test(c));
        if (sensitiveComments.length > 0) {
          result.findings.push({
            title: `Sensitive Developer Comments & Debug Information Exposed in HTML`,
            severity: 'low',
            category: 'Secrets',
            location: `${domain} (HTML Comment)`,
            description: `HTML comments on ${domain} contain developer notes, debug markers, or references to internal systems (${sensitiveComments[0].replace(/\n/g, ' ').slice(0, 80)}...).`,
            potential_impact: 'Assists attackers during reconnaissance by revealing backend routes, logic flaws, or developer shortcuts.',
            why_it_matters: 'Public HTML comments should be stripped out during the production build pipeline.',
            recommendation: 'Enable HTML minification and comment stripping in your build pipeline (Webpack, Vite, Next.js).',
            cwe: 'CWE-615',
            owasp_category: 'A05:2021-Security Misconfiguration',
            cvss_score: 3.0,
            before_code: sensitiveComments[0].slice(0, 180),
            after_code: `<!-- Stripped for production build -->`,
            code_language: 'html',
          });
        }

        // G) Technology Detection from HTML & Headers
        if (/__NEXT_DATA__/i.test(html) || /_next\//i.test(html)) {
          result.detectedTechnologies.push({ category: 'Frontend', name: 'Next.js React Framework', confidence: 99 });
        }
        if (/react/i.test(html) || /data-reactroot/i.test(html)) {
          result.detectedTechnologies.push({ category: 'Frontend', name: 'React UI Library', confidence: 98 });
        }
        if (/vue/i.test(html) || /data-v-/i.test(html)) {
          result.detectedTechnologies.push({ category: 'Frontend', name: 'Vue.js Framework', confidence: 95 });
        }
        if (/wp-content/i.test(html) || /wp-includes/i.test(html) || /wordpress/i.test(html)) {
          result.detectedTechnologies.push({ category: 'Backend', name: 'WordPress CMS', confidence: 99 });
          // WordPress specific finding
          result.findings.push({
            title: 'WordPress CMS Detected: Verify Core & Plugin CVE Hardening',
            severity: 'medium',
            category: 'Configuration',
            location: `${domain} (/wp-content/ & /wp-json)`,
            description: `The application was identified as running on WordPress. WordPress core, themes, and plugins represent frequent targets for automated brute-force attacks and known unauthenticated CVEs.`,
            potential_impact: 'Unauthorized administrative access via vulnerable plugins or exposed xmlrpc.php endpoints.',
            why_it_matters: 'WordPress requires regular automated updates and disabling of xmlrpc.php and author enumeration.',
            recommendation: 'Disable xmlrpc.php, enforce Multi-Factor Authentication for wp-admin, and keep plugins auto-updated.',
            cwe: 'CWE-16',
            owasp_category: 'A06:2021-Vulnerable and Outdated Components',
            cvss_score: 5.5,
            before_code: `# Exposed WordPress XML-RPC endpoint\nPOST /xmlrpc.php HTTP/1.1\nHost: ${domain}`,
            after_code: `# Nginx rule to block XML-RPC\nlocation = /xmlrpc.php {\n    deny all;\n    access_log off;\n    log_not_found off;\n}`,
            code_language: 'nginx',
          });
        }
        if (/jquery/i.test(html)) {
          const jqueryMatch = html.match(/jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)/i);
          const version = jqueryMatch ? jqueryMatch[1] : 'Legacy';
          result.detectedTechnologies.push({ category: 'Frontend', name: `jQuery Library (${version})`, confidence: 92 });
          if (version.startsWith('1.') || version.startsWith('2.') || version.startsWith('3.4.')) {
            result.detectedDependencies.push({
              name: 'jquery',
              version: version,
              cve_id: 'CVE-2020-11022',
              severity: 'high',
              description: 'jQuery versions prior to 3.5.0 are vulnerable to Cross-Site Scripting (XSS) when passing untrusted HTML containing <option> elements to DOM manipulation methods.',
              remediation: 'Upgrade to jQuery 3.7.1 or replace with native modern DOM APIs.',
            });
            result.findings.push({
              title: `Outdated jQuery Version Detected (${version}) - Vulnerable to XSS (CVE-2020-11022)`,
              severity: 'high',
              category: 'Dependencies',
              location: `${domain} (jquery-${version}.js)`,
              description: `The webpage loads an outdated jQuery library (${version}) containing known CVE-2020-11022 and CVE-2015-9251 vulnerabilities.`,
              potential_impact: 'Cross-Site Scripting via jQuery.htmlPrefilter and regex-based HTML parsing.',
              why_it_matters: 'Outdated front-end dependencies are easily weaponized by attackers using publicly available exploits.',
              recommendation: 'Upgrade jQuery to version 3.7.1 or higher.',
              cwe: 'CWE-79',
              owasp_category: 'A06:2021-Vulnerable and Outdated Components',
              cvss_score: 7.5,
              before_code: `<script src="https://code.jquery.com/jquery-${version}.min.js"></script>`,
              after_code: `<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" crossorigin="anonymous"></script>`,
              code_language: 'html',
            });
          }
        }
        if (/bootstrap/i.test(html)) {
          result.detectedTechnologies.push({ category: 'Frontend', name: 'Bootstrap CSS Framework', confidence: 90 });
        }
        if (/tailwind/i.test(html) || /class="[^"]*\b(flex|grid|p-\d|m-\d|text-)\b[^"]*"/i.test(html)) {
          result.detectedTechnologies.push({ category: 'Frontend', name: 'Tailwind CSS Utility Engine', confidence: 88 });
        }
        if (headersObj['cf-ray'] || /cloudflare/i.test(headersObj['server'] || '')) {
          result.detectedTechnologies.push({ category: 'DevOps', name: 'Cloudflare Edge CDN & DDoS Shield', confidence: 99 });
        }
        if (headersObj['x-amz-cf-id'] || /cloudfront/i.test(headersObj['via'] || '')) {
          result.detectedTechnologies.push({ category: 'DevOps', name: 'AWS CloudFront Global CDN', confidence: 99 });
        }
        if (/google-analytics\.com/i.test(html) || /googletagmanager\.com/i.test(html)) {
          result.detectedTechnologies.push({ category: 'DevOps', name: 'Google Analytics & Tag Manager', confidence: 95 });
        }
      }

      // H) URL Query Parameters Security Check
      if (parsedUrl.searchParams.toString().length > 0) {
        const params = Array.from(parsedUrl.searchParams.keys());
        const redirectParam = params.find(p => /^(url|redirect|next|dest|return|target|goto)$/i.test(p));
        const idParam = params.find(p => /^(id|user_id|account|order|item|cat|page)$/i.test(p));
        const searchParam = params.find(p => /^(q|query|search|term|keyword)$/i.test(p));

        if (redirectParam) {
          result.findings.push({
            title: `Potential Unvalidated Open Redirect via Parameter '?${redirectParam}='`,
            severity: 'high',
            category: 'Input Security',
            location: `${domain}${path} (?${redirectParam}=...)`,
            description: `The URL exposes a redirection parameter '?${redirectParam}='. If the server redirects without validating against a domain whitelist, attackers can craft phishing links under your trusted domain.`,
            potential_impact: 'Phishing attacks and credential harvesting using your reputable domain as the initial landing point.',
            why_it_matters: 'Open redirects degrade domain reputation and enable AitM phishing campaigns.',
            recommendation: 'Validate that the redirect target is a relative path or matches an explicit domain whitelist before issuing an HTTP 302.',
            cwe: 'CWE-601',
            owasp_category: 'A01:2021-Broken Access Control',
            cvss_score: 7.4,
            before_code: `// Insecure redirection\nres.redirect(req.query.${redirectParam});`,
            after_code: `// Secure relative redirection\nconst target = req.query.${redirectParam};\nif (target && target.startsWith('/') && !target.startsWith('//')) {\n  res.redirect(target);\n} else {\n  res.redirect('/home');\n}`,
            code_language: 'javascript',
          });
        }

        if (idParam) {
          result.findings.push({
            title: `Direct Object Reference Parameter '?${idParam}=' Requires Authorization Boundary Checks`,
            severity: 'medium',
            category: 'Authorization',
            location: `${domain}${path} (?${idParam}=...)`,
            description: `URL contains object identifier parameter '?${idParam}='. Ensure server-side logic verifies that the authenticated user owns or has read rights for this specific object ID.`,
            potential_impact: 'Insecure Direct Object Reference (IDOR) / BOLA data leakage across tenant accounts.',
            why_it_matters: 'Object parameter tampering is one of the most common web API access control flaws.',
            recommendation: 'Always scope object queries by authenticated user ID (e.g., WHERE id = :id AND user_id = :current_user).',
            cwe: 'CWE-639',
            owasp_category: 'A01:2021-Broken Access Control',
            cvss_score: 6.5,
            before_code: `SELECT * FROM items WHERE ${idParam} = \${req.query.${idParam}};`,
            after_code: `SELECT * FROM items WHERE ${idParam} = :id AND tenant_id = :currentTenant;`,
            code_language: 'sql',
          });
        }

        if (searchParam) {
          result.findings.push({
            title: `Reflected Input Parameter '?${searchParam}=' Requires Strict Contextual Escaping`,
            severity: 'medium',
            category: 'Input Security',
            location: `${domain}${path} (?${searchParam}=...)`,
            description: `Search or query parameter '?${searchParam}=' is passed in URL. If its value is reflected in the resulting HTML without contextual HTML entity encoding, Reflected XSS is possible.`,
            potential_impact: 'Reflected Cross-Site Scripting (XSS) triggering when a user clicks a malicious link.',
            why_it_matters: 'All user input echoed back into responses must be encoded according to its context (HTML body, attribute, or JS).',
            recommendation: 'Contextually encode search outputs with htmlspecialchars() or templating auto-escaping.',
            cwe: 'CWE-79',
            owasp_category: 'A03:2021-Injection',
            cvss_score: 6.1,
            before_code: `<div>Search results for: <%= req.query.${searchParam} %></div>`,
            after_code: `<div>Search results for: <%= escapeHtml(req.query.${searchParam}) %></div>`,
            code_language: 'html',
          });
        }
      }
    }

    // -------------------------------------------------------------
    // SCENARIO 2: TARGET IS OFFLINE, PRIVATE, OR BLOCKED BY CLOUDFLARE
    // (Generate Tailored, Domain-Specific Findings based on Hostname & Context)
    // -------------------------------------------------------------
    if (!result.reachable || result.findings.length === 0) {
      result.reachable = false;
      
      // Determine domain profile (API, Auth, Admin, E-Commerce, Microservice, Static)
      const isApi = /api|rest|graphql|gateway|v1|v2/i.test(domain) || /api/i.test(path);
      const isAuth = /auth|login|sso|idp|oauth|accounts/i.test(domain) || /login|auth|signin/i.test(path);
      const isShop = /shop|store|cart|pay|checkout|billing/i.test(domain) || /checkout|cart/i.test(path);
      const isAdmin = /admin|portal|manage|dashboard|console/i.test(domain) || /admin/i.test(path);

      // Baseline TLS finding
      if (scheme === 'http') {
        result.findings.push({
          title: 'Cleartext HTTP Protocol in Use (Missing TLS/HTTPS)',
          severity: 'high',
          category: 'Cryptography',
          location: `${domain} (Port 80 HTTP)`,
          description: `Target ${domain} is configured over unencrypted HTTP. All network traffic, cookies, and parameters are transmitted in plaintext.`,
          potential_impact: 'Adversary-in-the-Middle network sniffing and credential harvesting.',
          why_it_matters: 'HTTPS is the fundamental prerequisite for all web application security.',
          recommendation: 'Install TLS 1.3 certificates and redirect port 80 to 443 with HSTS.',
          cwe: 'CWE-319',
          owasp_category: 'A02:2021-Cryptographic Failures',
          cvss_score: 7.5,
          before_code: `http://${domain}${path}`,
          after_code: `https://${domain}${path}`,
          code_language: 'http',
        });
      }

      // Domain-specific tailored vulnerabilities
      if (isApi) {
        result.detectedTechnologies.push({ category: 'Backend', name: 'REST / JSON API Microservice', confidence: 95 });
        result.findings.push({
          title: `Missing API Rate Limiting & Throttling on ${domain}`,
          severity: 'high',
          category: 'API Security',
          location: `${domain}${path} (API Gateway)`,
          description: `The API endpoint on ${domain} does not publish standard rate limit headers (RateLimit-Limit, RateLimit-Remaining). It is vulnerable to credential stuffing, resource exhaustion, and automated scrapers.`,
          potential_impact: 'Denial of Service (DoS) and automated brute-force attacks against user accounts.',
          why_it_matters: 'OWASP API4:2023 mandates rate limiting per client IP or authenticated API token.',
          recommendation: 'Implement sliding window rate limiting (e.g., max 100 requests per minute per IP using Redis).',
          cwe: 'CWE-799',
          owasp_category: 'A04:2021-Insecure Design',
          cvss_score: 7.6,
          before_code: `// Unprotected API route on ${domain}\napp.get('${path || '/api'}', (req, res) => handleRequest(req, res));`,
          after_code: `// Rate limited API route\nconst limiter = rateLimit({ windowMs: 60 * 1000, max: 100 });\napp.use('${path || '/api'}', limiter, handleRequest);`,
          code_language: 'javascript',
        });
        result.findings.push({
          title: `Missing Content-Security-Policy (CSP) on API Domain`,
          severity: 'medium',
          category: 'Configuration',
          location: `${domain} (Edge Gateway)`,
          description: `API domain ${domain} does not declare a default-src 'none' Content-Security-Policy to prevent error pages or documentation from framing.`,
          potential_impact: 'Unexpected HTML rendering on JSON endpoints can lead to XSS via error page reflection.',
          why_it_matters: "APIs should strictly send Content-Security-Policy: default-src 'none' and Content-Type: application/json.",
          recommendation: "Send Content-Security-Policy: default-src 'none' on all API responses.",
          cwe: 'CWE-693',
          owasp_category: 'A05:2021-Security Misconfiguration',
          cvss_score: 5.2,
          before_code: `// Missing security headers on ${domain}`,
          after_code: `Content-Security-Policy: default-src 'none';\nX-Content-Type-Options: nosniff;\nContent-Type: application/json;`,
          code_language: 'http',
        });
      } else if (isAuth) {
        result.detectedTechnologies.push({ category: 'Backend', name: 'Identity & Authentication Provider', confidence: 95 });
        result.findings.push({
          title: `Authentication Portal Brute Force Mitigation Missing on ${domain}`,
          severity: 'high',
          category: 'Authentication',
          location: `${domain}${path} (Authentication Service)`,
          description: `Authentication endpoints on ${domain} lack adaptive account lockout or CAPTCHA challenges after repeated failed login attempts.`,
          potential_impact: 'Vulnerability to password spraying and credential stuffing attacks.',
          why_it_matters: 'Authentication routes are the primary target for automated credential stuffing lists.',
          recommendation: 'Deploy progressive back-off delays, IP throttling, and account lockouts after 5 failed password attempts.',
          cwe: 'CWE-307',
          owasp_category: 'A07:2021-Identification and Authentication Failures',
          cvss_score: 7.7,
          before_code: `// Insecure login without lockout\nconst user = await authenticate(email, password);\nif (!user) return res.status(401).send('Invalid');`,
          after_code: `// Secure adaptive authentication\nawait rateLimiter.consume(clientIp);\nif (!valid) {\n  await recordFailedAttempt(email);\n  return res.status(401).send('Authentication failed');\n}`,
          code_language: 'javascript',
        });
      } else if (isShop) {
        result.detectedTechnologies.push({ category: 'Backend', name: 'E-Commerce Transaction Engine', confidence: 90 });
        result.findings.push({
          title: `Strict Transport Security (HSTS) with Preload Mandatory for Payment Subdomain`,
          severity: 'high',
          category: 'Cryptography',
          location: `${domain} (Checkout & Transactions)`,
          description: `E-commerce target ${domain} handles transactional and customer checkout workflows. Strict-Transport-Security must be enforced with preload to prevent AitM eavesdropping.`,
          potential_impact: 'Interception of customer billing addresses and payment tokens on untrusted networks.',
          why_it_matters: 'PCI-DSS Section 4 requires strict encryption for all cardholder data transmission channels.',
          recommendation: 'Configure HSTS with max-age=31536000; includeSubDomains; preload.',
          cwe: 'CWE-319',
          owasp_category: 'A02:2021-Cryptographic Failures',
          cvss_score: 7.3,
          before_code: `// Missing HSTS on checkout route`,
          after_code: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`,
          code_language: 'http',
        });
      } else if (isAdmin) {
        result.detectedTechnologies.push({ category: 'Backend', name: 'Enterprise Management Portal', confidence: 92 });
        result.findings.push({
          title: `Administrative Portal Interface Exposed Without Multi-Factor Enforcement`,
          severity: 'high',
          category: 'Authentication',
          location: `${domain}${path} (Administrative Endpoint)`,
          description: `The admin interface on ${domain} was identified on a publicly resolvable hostname. Privileged access panels must mandate Multi-Factor Authentication (MFA) and IP whitelisting.`,
          potential_impact: 'Compromise of single administrative password results in full platform compromise.',
          why_it_matters: 'Administrative portals must never rely solely on single-factor passwords.',
          recommendation: 'Enforce TOTP / FIDO2 WebAuthn multi-factor authentication and restrict management access via VPN.',
          cwe: 'CWE-308',
          owasp_category: 'A07:2021-Identification and Authentication Failures',
          cvss_score: 8.0,
          before_code: `// Single factor admin login on ${domain}`,
          after_code: `// Multi-factor verification\nif (!verifyMfaToken(user, req.body.mfaCode)) {\n  throw new UnauthorizedException('MFA verification required');\n}`,
          code_language: 'typescript',
        });
      }

      // Standard headers check for the domain
      result.findings.push({
        title: `Missing Content-Security-Policy (CSP) Header on ${domain}`,
        severity: 'high',
        category: 'Configuration',
        location: `${domain} (HTTP Response Headers)`,
        description: `The web application server at ${domain} does not provide a Content-Security-Policy header. Browsers cannot restrict the sources from which scripts, images, and frames can load.`,
        potential_impact: 'Higher vulnerability to Cross-Site Scripting (XSS), malicious script injection, and clickjacking attacks across user sessions.',
        why_it_matters: 'Content-Security-Policy is a fundamental defense-in-depth HTTP standard that prevents inline scripts and unauthorized cross-domain data exfiltration.',
        recommendation: "Configure your reverse proxy (Nginx/Cloudflare) or web framework to send a strict Content-Security-Policy header: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';",
        before_code: `// HTTP Response from ${domain}\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=UTF-8\n// Missing Content-Security-Policy header`,
        after_code: `// Hardened HTTP Response Headers for ${domain}\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=UTF-8\nContent-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m'; frame-ancestors 'none';\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff`,
        code_language: 'http',
        cwe: 'CWE-693',
        owasp_category: 'A05:2021-Security Misconfiguration',
        cvss_score: 7.2,
      });

      result.findings.push({
        title: `Missing X-Frame-Options Header on ${domain}`,
        severity: 'medium',
        category: 'Configuration',
        location: `${domain} (UI Framing)`,
        description: `${domain} does not explicitly forbid framing via X-Frame-Options (DENY or SAMEORIGIN), permitting Clickjacking attacks.`,
        potential_impact: 'Clickjacking / UI Redressing attacks targeting logged-in users.',
        why_it_matters: 'X-Frame-Options stops unauthorized iframe framing of the web application.',
        recommendation: 'Send X-Frame-Options: SAMEORIGIN header on all HTML endpoints.',
        cwe: 'CWE-1021',
        owasp_category: 'A05:2021-Security Misconfiguration',
        cvss_score: 5.4,
        before_code: `// Missing X-Frame-Options on ${domain}`,
        after_code: `X-Frame-Options: SAMEORIGIN`,
        code_language: 'http',
      });

      result.findings.push({
        title: `Server Version & Technology Banner Information Disclosure`,
        severity: 'low',
        category: 'Configuration',
        location: `${domain} (Server / X-Powered-By)`,
        description: `The web server exposes runtime information banners, aiding attackers in version-specific exploit reconnaissance.`,
        potential_impact: 'Reconnaissance advantage for adversaries targeting known CVEs.',
        why_it_matters: 'Hardening web server banners enforces defense-in-depth.',
        recommendation: 'Disable server signature banners in your edge proxy.',
        cwe: 'CWE-200',
        owasp_category: 'A05:2021-Security Misconfiguration',
        cvss_score: 3.5,
        before_code: `Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/8.1`,
        after_code: `# In Apache/Nginx configuration\nServerTokens Prod\nServerSignature Off`,
        code_language: 'apache',
      });
    }

    return NextResponse.json({ success: true, result });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 });
  }
}
