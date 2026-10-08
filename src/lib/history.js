import { useSyncExternalStore } from 'react';

// Scan results live in the browser: the API runs on stateless serverless instances.
const KEY = 'vulnguard:scans:v1';
const MAX_SCANS = 25;
const listeners = new Set();
let cache = null;

function read() {
  if (cache) return cache;
  try {
    const parsed = JSON.parse(localStorage.getItem(KEY) || '[]');
    cache = Array.isArray(parsed) ? parsed.filter((s) => s && typeof s.id === 'string') : [];
  } catch {
    cache = [];
  }
  return cache;
}

function write(scans) {
  cache = scans;
  let toStore = scans;
  // Drop oldest entries until the payload fits the storage quota
  while (toStore.length) {
    try {
      localStorage.setItem(KEY, JSON.stringify(toStore));
      break;
    } catch {
      toStore = toStore.slice(0, -1);
    }
  }
  listeners.forEach((fn) => fn());
}

export function saveScan(scan) {
  write([scan, ...read().filter((s) => s.id !== scan.id)].slice(0, MAX_SCANS));
}

const SEVERITY_VALUES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const str = (v, max = 4000) => (typeof v === 'string' ? v.slice(0, max) : '');

/** Validate and normalise a report loaded from a JSON export. Throws on anything that is not one. */
export function importScan(raw) {
  if (!raw || typeof raw !== 'object' || typeof raw.target !== 'string' || !Array.isArray(raw.vulnerabilities)) {
    throw new Error('This file is not a VulnGuard JSON report.');
  }
  const vulnerabilities = raw.vulnerabilities.slice(0, 2000).map((v, i) => ({
    id: str(v?.id, 64) || `imported-${i}`,
    type: str(v?.type, 64),
    severity: SEVERITY_VALUES.has(v?.severity) ? v.severity : 'INFO',
    title: str(v?.title, 300) || 'Security finding',
    description: str(v?.description),
    evidence: str(v?.evidence),
    location: str(v?.location, 1000),
    cwe_id: str(v?.cwe_id, 32) || null,
    owasp_category: str(v?.owasp_category, 120),
  }));
  const patches = (Array.isArray(raw.patches) ? raw.patches : []).slice(0, 100).map((p) => ({
    vulnerability_id: str(p?.vulnerability_id, 64),
    vulnerability_ids: Array.isArray(p?.vulnerability_ids) ? p.vulnerability_ids.map((x) => str(x, 64)) : [],
    title: str(p?.title, 300),
    description: str(p?.description),
    original_code: str(p?.original_code, 20000) || null,
    patched_code: str(p?.patched_code, 20000) || null,
    references: Array.isArray(p?.references) ? p.references.map((r) => str(r, 500)).filter(Boolean) : [],
  }));
  const scan = {
    id: str(raw.id, 64) || crypto.randomUUID(),
    target: str(raw.target, 500),
    scan_type: ['dynamic', 'static', 'repo'].includes(raw.scan_type) ? raw.scan_type : 'static',
    started_at: str(raw.started_at, 40),
    completed_at: str(raw.completed_at, 40) || null,
    vulnerabilities,
    patches,
    summary: {},
    warnings: Array.isArray(raw.warnings) ? raw.warnings.map((w) => str(w, 300)).slice(0, 20) : [],
    stats: raw.stats && typeof raw.stats === 'object' ? { files_scanned: Number(raw.stats.files_scanned) || undefined } : {},
  };
  saveScan(scan);
  return scan;
}

export function getScan(id) {
  return read().find((s) => s.id === id) ?? null;
}

export function removeScan(id) {
  write(read().filter((s) => s.id !== id));
}

export function clearScans() {
  write([]);
}

function subscribe(fn) {
  listeners.add(fn);
  const onStorage = (e) => {
    if (e.key === KEY) {
      cache = null;
      fn();
    }
  };
  window.addEventListener('storage', onStorage);
  return () => {
    listeners.delete(fn);
    window.removeEventListener('storage', onStorage);
  };
}

export function useScanHistory() {
  return useSyncExternalStore(subscribe, read, () => []);
}
