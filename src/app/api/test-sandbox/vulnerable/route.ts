import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * Built-in Intentionally Vulnerable Test Target (Safe & Controlled)
 * Used to verify the scanner's behavioral analysis, data flow tracing, and header checks.
 */
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const search = url.searchParams.get('search') || '';

  // Vulnerable HTML response containing:
  // 1. Reflected parameter without HTML entity escaping
  // 2. DOM sink with controlled data-flow (location.hash -> decodeURIComponent -> innerHTML)
  // 3. Static innerHTML (to test false positive suppression!)
  // 4. Verbose database error disclosure signature
  // 5. Form action over HTTP
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerable Test Application - SecureLens Sandbox</title>
</head>
<body>
  <h1>Vulnerable Test Application (Security Sandbox)</h1>
  <p>This target is deliberately misconfigured to demonstrate scanner accuracy and data-flow verification.</p>
  
  <!-- 1. Reflected Input Vulnerability without Escaping -->
  <div id="search-reflection">
    ${search ? `Search results for: ${search}` : 'Enter a query in ?search='}
  </div>

  <!-- 2. Controllable DOM XSS Data Flow -->
  <div id="dynamic-content">Waiting for hash payload...</div>
  <script>
    // Source: location.hash -> Transformation: decodeURIComponent -> Sink: innerHTML
    const userHash = window.location.hash.substring(1);
    if (userHash) {
      const decoded = decodeURIComponent(userHash);
      document.getElementById('dynamic-content').innerHTML = decoded;
    }
  </script>

  <!-- 3. Static Trusted innerHTML (Must NOT be flagged as confirmed XSS!) -->
  <div id="static-badge"></div>
  <script>
    document.getElementById('static-badge').innerHTML = '<span class="status-pill">Active System Status</span>';
  </script>

  <!-- 4. Verbose Database Error Signature in HTML -->
  <div class="debug-panel" style="display:none;">
    Database Exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near 'WHERE id = 1'' at line 1
  </div>

  <!-- 5. Form with unencrypted action -->
  <form action="http://insecure-payment.internal/process" method="POST">
    <input type="password" name="password" placeholder="Enter password" />
    <button type="submit">Submit Insecure Form</button>
  </form>
</body>
</html>`;

  const response = new NextResponse(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      // Insecure headers configuration:
      // - Missing Content-Security-Policy
      // - Missing Strict-Transport-Security
      // - Missing X-Content-Type-Options: nosniff
      // - Weak Referrer-Policy
      'Referrer-Policy': 'unsafe-url',
      // - Wildcard CORS with credentials flag
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': 'true',
      'Server': 'Apache/2.4.41 (Ubuntu)',
      'X-Powered-By': 'Express',
      'SourceMap': '/bundles/app.js.map',
    },
  });

  // Set insecure session cookie (Missing HttpOnly, Missing Secure, Missing SameSite)
  response.cookies.set({
    name: 'test_session_id',
    value: 'insecure_token_987654321',
    path: '/',
    httpOnly: false,
    secure: false,
  });

  return response;
}
