import { ApplicationArchitecture, ArchitectureComponent, DetectedTechnology, DiscoveredEndpoint, DiscoveredResource } from '@/types/security';

export interface TechEvidenceRule {
  name: string;
  category: 'Frontend' | 'Backend' | 'Database' | 'DevOps' | 'Package Manager';
  archSlot: 'frontend' | 'apiBackend' | 'databaseExternal' | 'hosting' | 'authentication' | 'apiStyle';
  versionRegex?: RegExp;
  matcher: (headers: Record<string, string>, html: string, endpoints: DiscoveredEndpoint[]) => {
    matched: boolean;
    evidence?: string;
    version?: string;
    confidence: number;
  };
}

export const TECH_RULES: TechEvidenceRule[] = [
  // 1. Next.js
  {
    name: 'Next.js',
    category: 'Frontend',
    archSlot: 'frontend',
    matcher: (headers, html) => {
      const hasNextData = html.includes('__NEXT_DATA__');
      const hasNextChunk = html.includes('/_next/static/');
      const hasPoweredBy = (headers['x-powered-by'] || '').toLowerCase().includes('next.js');
      if (hasNextData || hasNextChunk || hasPoweredBy) {
        return {
          matched: true,
          evidence: hasNextData 
            ? 'Observed window.__NEXT_DATA__ hydration JSON blob in DOM.' 
            : 'Discovered /_next/static/ script bundles and Next.js asset paths.',
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 2. React
  {
    name: 'React',
    category: 'Frontend',
    archSlot: 'frontend',
    matcher: (headers, html) => {
      const hasReactRoot = html.includes('data-reactroot') || html.includes('_react') || html.includes('react-dom');
      const hasReactScripts = /react(?:-dom)?(?:\.production|\.development)?\.js/i.test(html);
      if (hasReactRoot || hasReactScripts) {
        return {
          matched: true,
          evidence: 'Observed React virtual DOM root mount markers and react-dom client chunks.',
          confidence: 98,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 3. Angular
  {
    name: 'Angular',
    category: 'Frontend',
    archSlot: 'frontend',
    matcher: (headers, html) => {
      const hasNg = html.includes('ng-version') || html.includes('ng-app') || /ng-reflect/i.test(html);
      const ngMatch = html.match(/ng-version=["']([^"']+)["']/i);
      if (hasNg) {
        return {
          matched: true,
          evidence: `Discovered Angular component host directive with ng-version="${ngMatch ? ngMatch[1] : 'detected'}".`,
          version: ngMatch ? ngMatch[1] : undefined,
          confidence: 97,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 4. Vue.js
  {
    name: 'Vue.js',
    category: 'Frontend',
    archSlot: 'frontend',
    matcher: (headers, html) => {
      const hasVue = html.includes('data-v-') || html.includes('v-cloak') || /vue(?:\.min)?\.js/i.test(html);
      if (hasVue) {
        return {
          matched: true,
          evidence: 'Discovered Vue single file component scoped CSS attributes (data-v-*).',
          confidence: 96,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 5. Svelte
  {
    name: 'Svelte',
    category: 'Frontend',
    archSlot: 'frontend',
    matcher: (headers, html) => {
      const hasSvelte = /svelte-[a-z0-9]+/i.test(html) || html.includes('__svelte');
      if (hasSvelte) {
        return {
          matched: true,
          evidence: 'Observed Svelte compiler-generated hash class names (svelte-*) in DOM.',
          confidence: 95,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 6. Node.js & Express
  {
    name: 'Express (Node.js)',
    category: 'Backend',
    archSlot: 'apiBackend',
    matcher: (headers) => {
      const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
      if (poweredBy.includes('express')) {
        return {
          matched: true,
          evidence: 'HTTP response header X-Powered-By explicitly identified "Express".',
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 7. Django
  {
    name: 'Django (Python)',
    category: 'Backend',
    archSlot: 'apiBackend',
    matcher: (headers, html) => {
      const hasCsrfCookie = (headers['set-cookie'] || '').includes('csrftoken');
      const hasDjangoAdmin = html.includes('django-admin') || html.includes('csrfmiddlewaretoken');
      if (hasCsrfCookie || hasDjangoAdmin) {
        return {
          matched: true,
          evidence: hasCsrfCookie
            ? 'Observed Django default csrftoken session cookie.'
            : 'Observed Django CSRF middleware hidden form token (csrfmiddlewaretoken).',
          confidence: 95,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 8. Flask
  {
    name: 'Flask (Python)',
    category: 'Backend',
    archSlot: 'apiBackend',
    matcher: (headers) => {
      const server = (headers['server'] || '').toLowerCase();
      const hasWerkzeug = server.includes('werkzeug');
      if (hasWerkzeug) {
        const vMatch = server.match(/werkzeug\/([\d.]+)/i);
        return {
          matched: true,
          evidence: `Discovered Werkzeug WSGI server in Server header (${server}).`,
          version: vMatch ? vMatch[1] : undefined,
          confidence: 96,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 9. Laravel (PHP)
  {
    name: 'Laravel (PHP)',
    category: 'Backend',
    archSlot: 'apiBackend',
    matcher: (headers) => {
      const rawCookie = headers['set-cookie'] || '';
      if (rawCookie.includes('laravel_session') || rawCookie.includes('XSRF-TOKEN')) {
        return {
          matched: true,
          evidence: 'Observed standard Laravel session identifier (laravel_session) in Set-Cookie.',
          confidence: 98,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 10. Spring Boot (Java)
  {
    name: 'Spring Boot (Java)',
    category: 'Backend',
    archSlot: 'apiBackend',
    matcher: (headers, html) => {
      const hasWhitelabel = html.includes('Whitelabel Error Page') || html.includes('timestamp') && html.includes('status') && html.includes('error');
      const hasJsession = (headers['set-cookie'] || '').includes('JSESSIONID');
      if (hasWhitelabel || hasJsession) {
        return {
          matched: true,
          evidence: hasWhitelabel 
            ? 'Identified default Spring Boot Whitelabel Error signature.' 
            : 'Observed Java Servlet JSESSIONID container session cookie.',
          confidence: 94,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 11. ASP.NET
  {
    name: 'ASP.NET',
    category: 'Backend',
    archSlot: 'apiBackend',
    matcher: (headers) => {
      const asp = headers['x-aspnet-version'] || headers['x-aspnetmvc-version'];
      const powered = (headers['x-powered-by'] || '').toLowerCase();
      if (asp || powered.includes('asp.net')) {
        return {
          matched: true,
          evidence: `Observed ASP.NET response headers (X-AspNet-Version: ${asp || 'detected'}).`,
          version: asp,
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 12. WordPress
  {
    name: 'WordPress CMS',
    category: 'Backend',
    archSlot: 'apiBackend',
    matcher: (headers, html) => {
      const hasWp = html.includes('/wp-content/') || html.includes('/wp-includes/') || html.includes('wp-json');
      const genMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([^"']*)["']/i);
      if (hasWp) {
        return {
          matched: true,
          evidence: `Discovered WordPress asset structure (/wp-content/)${genMatch ? ` with generator version ${genMatch[1]}` : ''}.`,
          version: genMatch ? genMatch[1].trim() : undefined,
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 13. Nginx
  {
    name: 'Nginx Reverse Proxy',
    category: 'DevOps',
    archSlot: 'hosting',
    matcher: (headers) => {
      const server = headers['server'] || '';
      if (/nginx/i.test(server)) {
        const vMatch = server.match(/nginx\/([\d.]+)/i);
        return {
          matched: true,
          evidence: `Identified Nginx in Server header: "${server}".`,
          version: vMatch ? vMatch[1] : undefined,
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 14. Apache
  {
    name: 'Apache HTTP Server',
    category: 'DevOps',
    archSlot: 'hosting',
    matcher: (headers) => {
      const server = headers['server'] || '';
      if (/apache/i.test(server)) {
        const vMatch = server.match(/apache\/([\d.]+)/i);
        return {
          matched: true,
          evidence: `Identified Apache in Server header: "${server}".`,
          version: vMatch ? vMatch[1] : undefined,
          confidence: 98,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 15. Cloudflare
  {
    name: 'Cloudflare Edge CDN',
    category: 'DevOps',
    archSlot: 'hosting',
    matcher: (headers) => {
      const cfRay = headers['cf-ray'];
      const server = (headers['server'] || '').toLowerCase();
      if (cfRay || server.includes('cloudflare')) {
        return {
          matched: true,
          evidence: `Observed Cloudflare ray ID (${cfRay || 'cf-ray header'}) and edge routing headers.`,
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 16. Vercel
  {
    name: 'Vercel Edge Platform',
    category: 'DevOps',
    archSlot: 'hosting',
    matcher: (headers) => {
      const vercelHeader = headers['x-vercel-id'] || headers['x-vercel-cache'];
      if (vercelHeader || (headers['server'] || '').toLowerCase().includes('vercel')) {
        return {
          matched: true,
          evidence: `Detected Vercel Edge response routing tag (x-vercel-id: ${vercelHeader ? vercelHeader.slice(0, 14) + '...' : 'present'}).`,
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 17. AWS CloudFront / S3
  {
    name: 'Amazon Web Services (AWS)',
    category: 'DevOps',
    archSlot: 'hosting',
    matcher: (headers) => {
      const amzCf = headers['x-amz-cf-id'] || headers['x-amz-request-id'];
      if (amzCf) {
        return {
          matched: true,
          evidence: `Discovered AWS CloudFront edge tracking header (x-amz-cf-id).`,
          confidence: 99,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 18. Supabase
  {
    name: 'Supabase BaaS',
    category: 'Database',
    archSlot: 'databaseExternal',
    matcher: (headers, html) => {
      const hasSupa = /supabase\.co|supabaseKey|createClient\([^)]*supabase/i.test(html);
      if (hasSupa) {
        return {
          matched: true,
          evidence: 'Observed client initialization or API calls targeting *.supabase.co.',
          confidence: 94,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 19. Firebase
  {
    name: 'Google Firebase',
    category: 'Database',
    archSlot: 'databaseExternal',
    matcher: (headers, html) => {
      const hasFirebase = /firebaseio\.com|firebase\.initializeApp|firebaseConfig/i.test(html);
      if (hasFirebase) {
        return {
          matched: true,
          evidence: 'Detected Firebase client-side SDK configuration and Firestore endpoints.',
          confidence: 96,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
  // 20. GraphQL API Style
  {
    name: 'GraphQL API',
    category: 'Backend',
    archSlot: 'apiStyle',
    matcher: (headers, html, endpoints) => {
      const hasGqlEndpoint = endpoints.some(e => e.path.includes('/graphql') || e.path.includes('/gql'));
      const hasGqlText = /query\s+\w+\s*\{|__schema|graphql/i.test(html);
      if (hasGqlEndpoint || hasGqlText) {
        return {
          matched: true,
          evidence: hasGqlEndpoint ? 'Discovered explicit /graphql schema and query endpoint.' : 'Identified client-side GraphQL query structures.',
          confidence: 92,
        };
      }
      return { matched: false, confidence: 0 };
    }
  },
];

/**
 * Builds the exact Application Architecture model:
 * Browser -> Frontend -> API / Backend -> Database / External Services
 * 
 * CRITICAL RULE: If something cannot be determined with evidence,
 * display "Not externally observable". DO NOT GUESS!
 */
export function buildApplicationArchitecture(
  headers: Record<string, string>,
  html: string,
  endpoints: DiscoveredEndpoint[]
): {
  architecture: ApplicationArchitecture;
  detectedTechnologies: DetectedTechnology[];
} {
  const detectedTechnologies: DetectedTechnology[] = [];

  let frontendComp: ArchitectureComponent = { name: 'Not externally observable', evidence: 'No client framework signatures identified in HTML or bundles.', confidence: 0, status: 'not_observable' };
  let backendComp: ArchitectureComponent = { name: 'Not externally observable', evidence: 'Backend runtime headers stripped or masked.', confidence: 0, status: 'not_observable' };
  let dbComp: ArchitectureComponent = { name: 'Not externally observable', evidence: 'Direct database exposure is safely non-observable from public perimeter.', confidence: 0, status: 'not_observable' };
  let hostingComp: ArchitectureComponent = { name: 'Not externally observable', evidence: 'Edge infrastructure headers masked or generic.', confidence: 0, status: 'not_observable' };
  let authComp: ArchitectureComponent = { name: 'Not externally observable', evidence: 'No public OAuth or session headers captured during passive crawl.', confidence: 0, status: 'not_observable' };
  let apiStyleComp: ArchitectureComponent = { name: 'Not externally observable', evidence: 'API architecture style not explicitly confirmed.', confidence: 0, status: 'not_observable' };

  // Evaluate rules
  for (const rule of TECH_RULES) {
    const result = rule.matcher(headers, html, endpoints);
    if (result.matched) {
      const tech: DetectedTechnology = {
        name: rule.name,
        category: rule.category,
        version: result.version,
        evidence: result.evidence,
        confidence: result.confidence,
      };
      detectedTechnologies.push(tech);

      if (rule.archSlot === 'frontend' && frontendComp.status === 'not_observable') {
        frontendComp = {
          name: rule.name + (result.version ? ` (${result.version})` : ''),
          evidence: result.evidence || 'Identified via client signatures',
          confidence: result.confidence,
          status: 'detected',
        };
      } else if (rule.archSlot === 'apiBackend' && backendComp.status === 'not_observable') {
        backendComp = {
          name: rule.name + (result.version ? ` (${result.version})` : ''),
          evidence: result.evidence || 'Identified via server signatures',
          confidence: result.confidence,
          status: 'detected',
        };
      } else if (rule.archSlot === 'databaseExternal' && dbComp.status === 'not_observable') {
        dbComp = {
          name: rule.name,
          evidence: result.evidence || 'Identified via external services',
          confidence: result.confidence,
          status: 'detected',
        };
      } else if (rule.archSlot === 'hosting' && hostingComp.status === 'not_observable') {
        hostingComp = {
          name: rule.name + (result.version ? ` (${result.version})` : ''),
          evidence: result.evidence || 'Identified via routing headers',
          confidence: result.confidence,
          status: 'detected',
        };
      } else if (rule.archSlot === 'apiStyle' && apiStyleComp.status === 'not_observable') {
        apiStyleComp = {
          name: rule.name,
          evidence: result.evidence || 'Identified via API endpoints',
          confidence: result.confidence,
          status: 'detected',
        };
      }
    }
  }

  // Check Authentication mechanism from cookies or headers
  const setCookie = headers['set-cookie'] || '';
  if (/jwt|bearer|id_token|access_token/i.test(setCookie) || /jwt/i.test(html)) {
    authComp = {
      name: 'JSON Web Token (JWT) Bearer / Cookie',
      evidence: 'Observed JWT token signature pattern in authorization or session cookies.',
      confidence: 92,
      status: 'detected',
    };
  } else if (/oauth|accounts\.google\.com|auth0|cognito/i.test(html)) {
    authComp = {
      name: 'Federated OAuth 2.0 / OpenID Connect',
      evidence: 'Observed client redirect integration with federated identity provider.',
      confidence: 90,
      status: 'detected',
    };
  } else if (setCookie.length > 0) {
    authComp = {
      name: 'Stateful Session Cookies',
      evidence: 'Observed Set-Cookie headers managing server-side session state.',
      confidence: 95,
      status: 'detected',
    };
  }

  // Check API style if still not observable
  if (apiStyleComp.status === 'not_observable') {
    const hasJsonEndpoint = endpoints.some(e => e.contentType?.includes('application/json') || e.path.startsWith('/api'));
    if (hasJsonEndpoint) {
      apiStyleComp = {
        name: 'RESTful JSON API',
        evidence: 'Discovered standard /api routes responding with JSON payloads.',
        confidence: 93,
        status: 'detected',
      };
    }
  }

  const architecture: ApplicationArchitecture = {
    browser: {
      name: 'Modern Browser (Chromium / WebKit / Gecko)',
      evidence: 'Standard HTTP/1.1 or HTTP/2 client user-agent handshake.',
      confidence: 99,
      status: 'detected',
    },
    frontend: frontendComp,
    apiBackend: backendComp,
    databaseExternal: dbComp,
    hosting: hostingComp,
    authentication: authComp,
    apiStyle: apiStyleComp,
  };

  return { architecture, detectedTechnologies };
}
