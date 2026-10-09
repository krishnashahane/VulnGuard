import { SEVERITIES, countBySeverity, riskBand, riskScore } from './severity';

function download(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const slug = (scan) =>
  `vulnguard-${scan.scan_type}-${String(scan.target).replace(/^https?:\/\//, '').replace(/[^a-z0-9.-]+/gi, '_').slice(0, 40)}`;

export function exportJson(scan) {
  download(`${slug(scan)}.json`, JSON.stringify(scan, null, 2), 'application/json');
}

export function exportMarkdown(scan) {
  const counts = countBySeverity(scan.vulnerabilities);
  const score = riskScore(scan.vulnerabilities);
  const patchFor = patchIndex(scan.patches);
  const fence = (code) => `\`\`\`\n${code.replace(/```/g, '`​``')}\n\`\`\``;
  const lines = [
    `# VulnGuard report`,
    '',
    `- **Target:** ${scan.target}`,
    `- **Type:** ${{ dynamic: 'Dynamic (DAST)', repo: 'Repository (SAST + dependencies)' }[scan.scan_type] || 'Static (SAST)'}`,
    `- **Completed:** ${new Date(scan.completed_at || scan.started_at).toISOString()}`,
    `- **Risk score:** ${score}% (${riskBand(score, scan.vulnerabilities.length).label})`,
    `- **Findings:** ${scan.vulnerabilities.length} (${SEVERITIES.map((s) => `${s} ${counts[s]}`).join(', ')})`,
    '',
  ];
  if (scan.checks?.length) {
    lines.push('| Check | Result |', '| --- | --- |');
    for (const c of scan.checks) lines.push(`| ${c.name} | ${c.status.replace('_', ' ')}: ${c.detail} |`);
    lines.push('');
  }
  for (const w of scan.warnings || []) lines.push(`> Note: ${w}`, '');
  scan.vulnerabilities.forEach((v, i) => {
    lines.push(`## ${i + 1}. [${v.severity}] ${v.title}`, '');
    if (v.owasp_category || v.cwe_id) lines.push(`${[v.owasp_category, v.cwe_id].filter(Boolean).join(' / ')}`, '');
    if (v.description) lines.push(v.description, '');
    if (v.location) lines.push(`**Location:** \`${v.location}\``, '');
    if (v.evidence) lines.push('**Evidence:**', '', fence(v.evidence), '');
    const p = patchFor[v.id];
    if (p) {
      lines.push(`**Fix:** ${p.title}`, '');
      if (p.patched_code) lines.push(fence(p.patched_code), '');
    }
  });
  download(`${slug(scan)}.md`, lines.join('\n'), 'text/markdown');
}

export function patchIndex(patches = []) {
  const map = {};
  for (const p of patches) {
    for (const id of p.vulnerability_ids?.length ? p.vulnerability_ids : [p.vulnerability_id]) map[id] = p;
  }
  return map;
}
