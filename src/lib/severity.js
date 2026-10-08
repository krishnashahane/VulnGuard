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

export function riskLabel(counts) {
  if (counts.CRITICAL) return { label: 'Critical risk', tone: 'CRITICAL' };
  if (counts.HIGH) return { label: 'High risk', tone: 'HIGH' };
  if (counts.MEDIUM) return { label: 'Moderate risk', tone: 'MEDIUM' };
  if (counts.LOW || counts.INFO) return { label: 'Low risk', tone: 'LOW' };
  return { label: 'No issues found', tone: null };
}
