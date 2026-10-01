import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Built-in Hardened Secure Test Target
 * Demonstrates that the scanner produces 0 vulnerabilities / Informational for hardened targets.
 */
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const rawSearch = url.searchParams.get('search') || '';
  const safeSearch = escapeHtml(rawSearch);
  const nonce = 'rAnd0mSecur3N0nce99';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Hardened Secure Test Application - SecureLens Sandbox</title>
</head>
<body>
  <h1>Hardened Secure Test Application</h1>
  <p>This target implements defense-in-depth best practices.</p>

  <!-- 1. Strictly Escaped Output Reflection -->
  <div id="search-reflection">
    ${safeSearch ? `Search results for: ${safeSearch}` : 'No query provided.'}
  </div>

  <!-- 2. Safe DOM Handling via textContent (Zero DOM XSS) -->
  <div id="dynamic-content">Securely initialized</div>
  <script nonce="${nonce}">
    const userHash = window.location.hash.substring(1);
    if (userHash) {
      // Safe sink: textContent instead of innerHTML
      document.getElementById('dynamic-content').textContent = userHash;
    }
  </script>

  <!-- 3. Form with Encrypted HTTPS Destination & Anti-CSRF Token -->
  <form action="https://api.securelens.local/v1/auth/login" method="POST">
    <input type="hidden" name="_csrf" value="b8f9e2d1c7a4" />
    <input type="password" name="password" autocomplete="current-password" placeholder="Password" />
    <button type="submit">Secure Sign In</button>
  </form>
</body>
</html>`;

  const response = new NextResponse(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://api.securelens.local;`,
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cache-Control': 'no-store, max-age=0',
      'Access-Control-Allow-Origin': 'https://app.securelens.local',
      'Access-Control-Allow-Credentials': 'true',
    },
  });

  // Hardened Cookie
  response.cookies.set({
    name: 'secure_session_id',
    value: 'hardened_cryptographic_token_42a8b9',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600,
  });

  return response;
}
