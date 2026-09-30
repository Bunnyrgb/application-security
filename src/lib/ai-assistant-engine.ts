import { Vulnerability, AIChatMessage } from '@/types/security';

export interface AIResponse {
  message: string;
  codeSnippet?: {
    language: string;
    code: string;
    type: 'before' | 'after' | 'example';
  };
  suggestedActions?: string[];
}

export function generateAIAnswer(
  query: string,
  selectedVulnerability?: Vulnerability,
  allVulnerabilities: Vulnerability[] = []
): AIResponse {
  const normalizedQuery = query.toLowerCase();

  // 1. "Which issues should I fix first?" / Prioritization triage
  if (
    normalizedQuery.includes('which issues should i fix first') ||
    normalizedQuery.includes('priority') ||
    normalizedQuery.includes('fix first') ||
    normalizedQuery.includes('where to start')
  ) {
    const criticals = allVulnerabilities.filter(v => v.severity === 'critical' && v.status === 'confirmed');
    const highs = allVulnerabilities.filter(v => v.severity === 'high' && v.status === 'confirmed');

    let triageText = `### 🎯 Remediation Priority Matrix\n\n`;
    triageText += `Based on live attack surface analysis and CVSS scoring, address issues in this exact order:\n\n`;

    if (criticals.length > 0) {
      triageText += `**Tier 1: Immediate Triage (Critical - CVSS > 9.0)**\n`;
      criticals.forEach((c, idx) => {
        triageText += `${idx + 1}. **${c.title}** (${c.cwe_id}) at \`${c.location}\`\n   *Reason*: Directly exploitable remotely with zero authentication required.\n`;
      });
      triageText += `\n`;
    }

    if (highs.length > 0) {
      triageText += `**Tier 2: High Urgency (High - CVSS 7.0 - 8.9)**\n`;
      highs.forEach((h, idx) => {
        triageText += `${idx + 1}. **${h.title}** (${h.cwe_id}) at \`${h.location}\`\n   *Reason*: Breaks authorization boundaries and enables privilege escalation.\n`;
      });
    }

    return {
      message: triageText,
      suggestedActions: [
        'How can I fix the Critical SQL Injection?',
        'Show me a secure implementation for Stripe keys',
        'Explain this vulnerability to my team'
      ]
    };
  }

  // 2. Specific Vulnerability Context
  if (selectedVulnerability) {
    const v = selectedVulnerability;

    // "Why is this vulnerability dangerous?"
    if (normalizedQuery.includes('why') || normalizedQuery.includes('dangerous') || normalizedQuery.includes('risk')) {
      return {
        message: `### ⚠️ Risk Analysis: ${v.title}\n\n**Severity Level**: ${v.severity.toUpperCase()} (CVSS ${v.cvss_score})\n**Standard**: ${v.cwe_id} | ${v.owasp_category}\n\n**Why it is dangerous:**\n${v.why_it_matters}\n\n**Potential Impact in Production:**\n${v.potential_impact}\n\nAn attacker discovering this weakness at \`${v.location}\` can exploit standard automation tools to bypass perimeter firewalls and compromise data integrity.`,
        suggestedActions: [
          `How can I fix this?`,
          `Show me a secure implementation in TypeScript`,
          `Explain this in simple English`,
          `Explain this vulnerability to my team`
        ]
      };
    }

    // "Explain this in simple English"
    if (normalizedQuery.includes('simple english') || normalizedQuery.includes('simple terms') || normalizedQuery.includes('layman')) {
      let simpleExplanation = '';
      if (v.category === 'Input Security') {
        simpleExplanation = `Think of this like ordering at a drive-thru. Instead of just ordering a burger, someone whispers secret instructions into the microphone that tells the kitchen to empty the cash register and hand it out the window. Because the system doesn't check if the order has funny words in it, the database follows those malicious instructions blindly.`;
      } else if (v.category === 'Secrets') {
        simpleExplanation = `Imagine printing the master keys to your bank's vault right on the back of your business cards and handing them out to strangers. Putting live secret keys directly in the code means anyone who ever sees this file can spend your company's money or access private customer records.`;
      } else if (v.category === 'Authorization') {
        simpleExplanation = `Imagine a hotel where every room key opens every single door. A customer with room key #101 can simply walk into room #102, #103, and #200 without anyone stopping them. That is what Insecure Direct Object Reference (IDOR) is.`;
      } else {
        simpleExplanation = `The application is missing a standard safety check. Without this check, someone could exploit this code to see private data or disrupt normal operations.`;
      }

      return {
        message: `### 💡 Plain English Explanation\n\n${simpleExplanation}\n\n**Summary:**\nWe need to add a security check so that users cannot perform actions outside their allowed permissions.`,
        suggestedActions: [
          'Show me a secure implementation.',
          'How can I fix this?',
          'Which issues should I fix first?'
        ]
      };
    }

    // "Explain this vulnerability to my team"
    if (normalizedQuery.includes('team') || normalizedQuery.includes('stakeholder') || normalizedQuery.includes('management')) {
      return {
        message: `### 📋 Team & Stakeholder Briefing\n\n**Vulnerability**: ${v.title}\n**Severity**: ${v.severity.toUpperCase()} (${v.cwe_id})\n**Impact Level**: High Business Risk\n\n**What happened:**\nA security audit identified a code pattern at \`${v.location}\` that does not follow defensive engineering standards.\n\n**Business & Compliance Consequences:**\n* Potential breach of customer data violating GDPR / CCPA / PCI-DSS compliance.\n* Reputational risk and operational downtime if exploited.\n\n**Action Plan:**\n1. Developer will apply the recommended parameterized/secure pattern.\n2. QA will run an automated regression test.\n3. SecureLens rescan will verify closure and score improvement.`,
        suggestedActions: [
          'Show me a secure implementation.',
          'What security practices should I add?',
          'Mark as Fixed'
        ]
      };
    }

    // "How can I fix this?" / "Show me a secure implementation"
    if (
      normalizedQuery.includes('fix') ||
      normalizedQuery.includes('secure implementation') ||
      normalizedQuery.includes('code') ||
      normalizedQuery.includes('example') ||
      normalizedQuery.includes('how to')
    ) {
      return {
        message: `### 🛡️ Recommended Secure Implementation\n\n**Remediation Guide:**\n${v.recommended_fix}\n\nHere is the exact drop-in refactor for **${v.location}**:`,
        codeSnippet: {
          language: v.code_language || 'typescript',
          code: v.after_code || '// Secure implementation\n// Replace unsafe input parsing with strict schema validation',
          type: 'after',
        },
        suggestedActions: [
          'Explain this in simple English.',
          'Why is this vulnerability dangerous?',
          'What security practices should I add?'
        ]
      };
    }
  }

  // 3. "What security practices should I add?" / Best practices
  if (normalizedQuery.includes('practice') || normalizedQuery.includes('recommendation') || normalizedQuery.includes('standards')) {
    return {
      message: `### 🛡️ Core Defensive Security Practices to Implement\n\n1. **Zero-Trust Input Validation**: Never trust client-side data. Enforce runtime schema validation with Zod, Joi, or Pydantic.\n2. **Parameterized Data Access**: Disallow string concatenation in database layers. Use parameterized queries or secure ORMs.\n3. **Centralized Secret Management**: Remove all hardcoded credentials. Store secrets in AWS Secrets Manager, HashiCorp Vault, or encrypted environment variables.\n4. **Automated CI/CD Security Gates**: Add SecureLens CLI to your GitHub Actions / GitLab CI pipeline to fail builds on Critical or High CVEs.\n5. **Least-Privilege RBAC & Row Level Security**: Enforce tenant ownership at the database layer using Postgres RLS policies.`,
      suggestedActions: [
        'Which issues should I fix first?',
        'How can I fix the Critical SQL Injection?',
        'Explain this vulnerability to my team'
      ]
    };
  }

  // Generic fallback query response
  return {
    message: `### 🤖 SecureLens AI Security Analyst\n\nI have analyzed your application posture across **${allVulnerabilities.length} active findings**.\n\nYou can ask me:\n- *"Why is this vulnerability dangerous?"*\n- *"How can I fix this?"*\n- *"Show me a secure implementation."*\n- *"Explain this in simple English."*\n- *"Which issues should I fix first?"*\n- *"Explain this vulnerability to my team."*`,
    suggestedActions: [
      'Which issues should I fix first?',
      'Show me a secure implementation.',
      'What security practices should I add?'
    ]
  };
}
