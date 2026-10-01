import { NextRequest, NextResponse } from 'next/server';
import { Scan, ScanComparison, Vulnerability } from '@/types/security';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { scan1, scan2 }: { scan1: Scan; scan2: Scan } = body;

    if (!scan1 || !scan2) {
      return NextResponse.json({ error: 'Both scan1 and scan2 are required for comparison.' }, { status: 400 });
    }

    const vulns1: Vulnerability[] = scan1.vulnerabilities || [];
    const vulns2: Vulnerability[] = scan2.vulnerabilities || [];

    // Helper key generator
    const getVulnKey = (v: Vulnerability) => `${v.cwe_id}_${v.title.toLowerCase().replace(/[^a-z0-9]/g, '')}`;

    const keys1 = new Set(vulns1.map(getVulnKey));
    const keys2 = new Set(vulns2.map(getVulnKey));

    // Fixed: in scan 1, but NOT in scan 2 (or explicitly marked fixed in scan 2)
    const fixedVulns = vulns1.filter(v => !keys2.has(getVulnKey(v)) || vulns2.some(v2 => getVulnKey(v2) === getVulnKey(v) && v2.status === 'fixed'));
    
    // Still Open: in both scan 1 and scan 2 with active status
    const stillOpenVulns = vulns2.filter(v => keys1.has(getVulnKey(v)) && v.status !== 'fixed' && v.status !== 'false_positive');
    
    // New: in scan 2, but NOT in scan 1
    const newVulns = vulns2.filter(v => !keys1.has(getVulnKey(v)) && v.status !== 'fixed' && v.status !== 'false_positive');
    
    // False Positives in scan 2
    const falsePositives = vulns2.filter(v => v.status === 'false_positive');

    const comparison: ScanComparison = {
      scanId1: scan1.id,
      scanId2: scan2.id,
      target: scan2.target_identifier || scan1.target_identifier,
      date1: scan1.completed_at || scan1.started_at,
      date2: scan2.completed_at || scan2.started_at,
      scoreBefore: scan1.score,
      scoreAfter: scan2.score,
      fixedCount: fixedVulns.length,
      stillOpenCount: stillOpenVulns.length,
      newCount: newVulns.length,
      falsePositiveCount: falsePositives.length,
      fixedVulnerabilityIds: fixedVulns.map(v => v.id),
      openVulnerabilityIds: stillOpenVulns.map(v => v.id),
      newVulnerabilityIds: newVulns.map(v => v.id),
    };

    return NextResponse.json({ success: true, comparison });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Comparison failed' }, { status: 500 });
  }
}
