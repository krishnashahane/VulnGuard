export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const SEVERITY_META = {
  CRITICAL: { label: 'Critical', text: 'text-sev-critical', bg: 'bg-sev-critical', ring: 'border-sev-critical/40' },
  HIGH: { label: 'High', text: 'text-sev-high', bg: 'bg-sev-high', ring: 'border-sev-high/40' },
  MEDIUM: { label: 'Medium', text: 'text-sev-medium', bg: 'bg-sev-medium', ring: 'border-sev-medium/40' },
  LOW: { label: 'Low', text: 'text-sev-low', bg: 'bg-sev-low', ring: 'border-sev-low/40' },
  INFO: { label: 'Info', text: 'text-sev-info', bg: 'bg-sev-info', ring: 'border-sev-info/40' },
};

export const normalizeSeverity = (s) => (SEVERITY_META[s?.toUpperCase?.()] ? s.toUpperCase() : 'INFO');

export function countBySeverity(vulns = []) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const v of vulns) counts[normalizeSeverity(v.severity)] += 1;
  return counts;
}

// Mirrors backend/scanner/models.py: findings combine as independent risks, so one critical alone is 50%.
const RISK_WEIGHTS = { CRITICAL: 0.5, HIGH: 0.3, MEDIUM: 0.06, LOW: 0.02, INFO: 0 };

export function riskScore(vulns = []) {
  const safe = vulns.reduce((p, v) => p * (1 - RISK_WEIGHTS[normalizeSeverity(v.severity)]), 1);
  return Math.round((1 - safe) * 100);
}

export function riskBand(score, findings = 0) {
  if (score >= 50) return { label: 'Critical risk', tone: 'CRITICAL' };
  if (score >= 25) return { label: 'High risk', tone: 'HIGH' };
  if (score >= 5) return { label: 'Moderate risk', tone: 'MEDIUM' };
  if (score >= 1) return { label: 'Low risk', tone: 'LOW' };
  if (findings) return { label: 'Informational only', tone: 'INFO' };
  return { label: 'No issues found', tone: null };
}
