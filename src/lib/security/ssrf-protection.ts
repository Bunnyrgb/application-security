export interface SSRFValidationResult {
  valid: boolean;
  sanitizedUrl?: string;
  error?: string;
  isSandboxTarget?: boolean;
}

/**
 * Validates and sanitizes scanner target URLs to prevent Server-Side Request Forgery (SSRF)
 * Blocks internal networks, loopbacks, cloud metadata endpoints, and non-HTTP schemes.
 */
export function validateTargetUrl(rawUrl: string, allowSandbox: boolean = true): SSRFValidationResult {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, error: 'Empty or invalid URL provided.' };
  }

  const trimmed = rawUrl.trim();
  let urlObj: URL;

  try {
    const formatted = trimmed.startsWith('http://') || trimmed.startsWith('https://') 
      ? trimmed 
      : `https://${trimmed}`;
    urlObj = new URL(formatted);
  } catch {
    return { valid: false, error: 'Malformed URL format. Expected valid FQDN or HTTPS endpoint.' };
  }

  // Scheme restriction: only HTTP and HTTPS allowed
  if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
    return { valid: false, error: `Disallowed protocol scheme "${urlObj.protocol}". Only HTTP/HTTPS allowed.` };
  }

  const hostname = urlObj.hostname.toLowerCase();

  // Special check: Localhost sandbox testing for built-in safe test apps
  if ((hostname === 'localhost' || hostname === '127.0.0.1') && allowSandbox && urlObj.pathname.includes('/api/test-sandbox/')) {
    return {
      valid: true,
      sanitizedUrl: urlObj.toString(),
      isSandboxTarget: true,
    };
  }

  // 1. Loopback detection
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname.startsWith('127.') ||
    hostname.endsWith('.localhost')
  ) {
    return {
      valid: false,
      error: 'Security Policy Violation: Loopback addresses (127.0.0.1 / localhost) are blocked to prevent SSRF.',
    };
  }

  // 2. Cloud Metadata Endpoint Protection (AWS / GCP / Azure / DigitalOcean)
  if (
    hostname === '169.254.169.254' ||
    hostname === 'metadata.google.internal' ||
    hostname.startsWith('169.254.')
  ) {
    return {
      valid: false,
      error: 'Security Policy Violation: Cloud provider metadata endpoint (169.254.169.254) is strictly forbidden.',
    };
  }

  // 3. Private RFC 1918 IP address ranges
  // 10.0.0.0 – 10.255.255.255
  // 172.16.0.0 – 172.31.255.255
  // 192.168.0.0 – 192.168.255.255
  const ipv4Match = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const octet1 = parseInt(ipv4Match[1], 10);
    const octet2 = parseInt(ipv4Match[2], 10);

    if (octet1 === 10) {
      return { valid: false, error: 'Security Policy Violation: RFC 1918 Private Class A (10.0.0.0/8) is blocked.' };
    }
    if (octet1 === 172 && octet2 >= 16 && octet2 <= 31) {
      return { valid: false, error: 'Security Policy Violation: RFC 1918 Private Class B (172.16.0.0/12) is blocked.' };
    }
    if (octet1 === 192 && octet2 === 168) {
      return { valid: false, error: 'Security Policy Violation: RFC 1918 Private Class C (192.168.0.0/16) is blocked.' };
    }
    if (octet1 === 0 || octet1 >= 224) {
      return { valid: false, error: 'Security Policy Violation: Broadcast / Multicast / Reserved IP ranges are blocked.' };
    }
  }

  // 4. DNS Rebinding / Disallowed Internal TLDs
  if (
    hostname.endsWith('.internal') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.corp') ||
    hostname.endsWith('.home') ||
    hostname.endsWith('.arpa')
  ) {
    return {
      valid: false,
      error: `Security Policy Violation: Internal corporate top-level domain (*.${hostname.split('.').pop()}) is blocked.`,
    };
  }

  return {
    valid: true,
    sanitizedUrl: urlObj.toString(),
    isSandboxTarget: false,
  };
}
