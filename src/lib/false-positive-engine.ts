import { Vulnerability, TriageStatus, ConfidenceLevel } from '@/types/security';

export interface FalsePositiveRuleResult {
  isFalsePositive: boolean;
  adjustedStatus?: TriageStatus;
  adjustedConfidence?: ConfidenceLevel;
  suppressionReason?: string;
}

/**
 * Dedicated False Positive Engine
 * Evaluates candidate findings against context-aware heuristic rules to prevent alert fatigue
 */
export class FalsePositiveEngine {
  /**
   * Evaluates a candidate vulnerability and determines if it should be marked as
   * false positive, informational, or adjusted in confidence/severity.
   */
  public static evaluateFinding(v: Partial<Vulnerability>): FalsePositiveRuleResult {
    const title = (v.title || '').toLowerCase();
    const location = (v.location || '').toLowerCase();
    const evidence = (v.evidence || '').toLowerCase();
    const beforeCode = (v.before_code || '').toLowerCase();

    // RULE 1: Static innerHTML / outerHTML with trusted static content
    if (title.includes('xss') || title.includes('innerhtml')) {
      if (v.data_flow && !v.data_flow.untrustedInputReachesSink) {
        return {
          isFalsePositive: true,
          adjustedStatus: 'informational',
          adjustedConfidence: 'low',
          suppressionReason: 'DOM sink receives static or internal trusted data only. No external attacker-controlled data flow identified.',
        };
      }
      if (beforeCode && (/innerHTML\s*=\s*['"`][^$]*['"`]/i.test(beforeCode) && !beforeCode.includes('${'))) {
        return {
          isFalsePositive: true,
          adjustedStatus: 'informational',
          adjustedConfidence: 'low',
          suppressionReason: 'innerHTML assignment contains a hardcoded string literal with no dynamic interpolation.',
        };
      }
    }

    // RULE 2: Public Client-Side API Keys
    // (e.g. Google Maps JS key, Firebase apiKey, Supabase public anon key, Stripe publishable key)
    if (title.includes('secret') || title.includes('api key') || title.includes('credential')) {
      const isPublicClientKey = 
        /pk_test_|pk_live_|firebase.*apiKey|supabase.*anon|google.*maps|analytics.*key|NEXT_PUBLIC_/i.test(beforeCode) ||
        /pk_test_|pk_live_|firebase.*apiKey|supabase.*anon|google.*maps|analytics.*key|NEXT_PUBLIC_/i.test(evidence);

      if (isPublicClientKey) {
        return {
          isFalsePositive: false,
          adjustedStatus: 'informational',
          adjustedConfidence: 'high',
          suppressionReason: 'Key is identified as a public client-side identifier intentionally exposed for browser operation (e.g. Supabase anon key, Stripe PK, or Google Maps). Verify domain restrictions in provider console.',
        };
      }
    }

    // RULE 3: Missing CSP on static API / JSON endpoints or non-script resources
    if (title.includes('content-security-policy') || title.includes('csp')) {
      if (location.includes('.json') || location.includes('.png') || location.includes('.css') || location.includes('api/health')) {
        return {
          isFalsePositive: true,
          adjustedStatus: 'informational',
          adjustedConfidence: 'low',
          suppressionReason: 'Endpoint serves static non-HTML data or raw JSON where client-side script execution is not interpreted by browsers.',
        };
      }
    }

    // RULE 4: robots.txt / sitemap.xml presence
    if (location.includes('robots.txt') || location.includes('sitemap.xml') || location.includes('security.txt')) {
      if (!title.includes('sensitive') && !title.includes('leak')) {
        return {
          isFalsePositive: false,
          adjustedStatus: 'informational',
          adjustedConfidence: 'high',
          suppressionReason: 'Public metadata resource used for attack surface discovery, not an exploitable vulnerability.',
        };
      }
    }

    // RULE 5: HSTS missing preload
    if (title.includes('hsts') && (title.includes('preload') || title.includes('subdomains'))) {
      return {
        isFalsePositive: false,
        adjustedStatus: 'potential',
        adjustedConfidence: 'medium',
        suppressionReason: 'Configuration hardening recommendation. Base TLS encryption is present.',
      };
    }

    // RULE 6: Wildcard CORS on public GET-only APIs without credentials
    if (title.includes('cors') && !evidence.includes('credentials: true')) {
      if (location.includes('/public') || location.includes('/feed') || location.includes('/v1/open')) {
        return {
          isFalsePositive: false,
          adjustedStatus: 'informational',
          adjustedConfidence: 'medium',
          suppressionReason: 'Public read-only API endpoint where Access-Control-Allow-Origin: * is intentional and poses no cross-site state tampering risk without credentials.',
        };
      }
    }

    return { isFalsePositive: false };
  }

  /**
   * Refines an entire list of findings through the false positive detection layer
   */
  public static filterAndClassifyFindings(findings: Vulnerability[]): {
    classifiedFindings: Vulnerability[];
    falsePositiveCount: number;
    potentialCount: number;
    confirmedCount: number;
    informationalCount: number;
  } {
    let falsePositiveCount = 0;
    let potentialCount = 0;
    let confirmedCount = 0;
    let informationalCount = 0;

    const classifiedFindings = findings.map(f => {
      const evaluation = this.evaluateFinding(f);
      const updated = { ...f };

      if (evaluation.adjustedStatus) {
        updated.status = evaluation.adjustedStatus;
      }
      if (evaluation.adjustedConfidence) {
        updated.confidence = evaluation.adjustedConfidence;
      }
      if (evaluation.suppressionReason) {
        updated.triage_reason = evaluation.suppressionReason;
      }

      if (updated.status === 'false_positive') falsePositiveCount++;
      else if (updated.status === 'confirmed') confirmedCount++;
      else if (updated.status === 'potential') potentialCount++;
      else if (updated.status === 'informational') informationalCount++;

      return updated;
    });

    return {
      classifiedFindings,
      falsePositiveCount,
      potentialCount,
      confirmedCount,
      informationalCount,
    };
  }
}
