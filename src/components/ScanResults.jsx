import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'motion/react';
import { AlertTriangle, Braces, FileDown, FileText, Printer, Search, ShieldCheck } from 'lucide-react';
import VulnerabilityCard from './VulnerabilityCard';
import { SEVERITIES, SEVERITY_META, countBySeverity, riskLabel } from '../lib/severity';
import { exportJson, exportMarkdown, patchIndex } from '../lib/export';

function duration(scan) {
  if (!scan.started_at || !scan.completed_at) return null;
  const ms = new Date(scan.completed_at) - new Date(scan.started_at);
  if (!Number.isFinite(ms) || ms < 0) return null;
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export default function ScanResults({ scan, showReportLink = false, scrollIntoView = false }) {
  const reduce = useReducedMotion();
  const ref = useRef(null);

  useEffect(() => {
    if (scrollIntoView) ref.current?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
  }, [scrollIntoView, reduce, scan?.id]);

  const [filter, setFilter] = useState(null);
  const [query, setQuery] = useState('');
  const vulns = useMemo(() => scan?.vulnerabilities ?? [], [scan]);
  const counts = useMemo(() => countBySeverity(vulns), [vulns]);
  const patches = useMemo(() => patchIndex(scan?.patches), [scan]);
  if (!scan) return null;

  const risk = riskLabel(counts);
  const q = query.trim().toLowerCase();
  const visible = vulns.filter(
    (v) =>
      (!filter || v.severity === filter) &&
      (!q || [v.title, v.location, v.cwe_id, v.description].some((f) => f?.toLowerCase().includes(q))),
  );
  const typeLabel = { dynamic: 'Dynamic scan', repo: 'Repository scan' }[scan.scan_type] || 'Static analysis';
  const filesScanned = scan.stats?.files_scanned;
  const took = duration(scan);
  const finished = new Date(scan.completed_at || scan.started_at);

  return (
    <motion.section
      ref={ref}
      initial={reduce ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="scroll-mt-24 space-y-6"
      aria-label="Scan results"
    >
      <div className="surface p-5 sm:p-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 space-y-1.5">
            <p className={`text-sm font-medium ${risk.tone ? SEVERITY_META[risk.tone].text : 'text-primary'}`}>{risk.label}</p>
            <h2 className="break-all font-mono text-lg font-medium sm:text-xl">{scan.target}</h2>
            <p className="text-sm muted">
              {typeLabel}
              {filesScanned > 1 && ` of ${filesScanned} files`}
              {' on '}
              {Number.isNaN(finished.getTime()) ? 'unknown date' : finished.toLocaleString()}
              {took && `, took ${took}`}
            </p>
          </div>

          <div className="no-print flex flex-wrap gap-2">
            {showReportLink && (
              <Link to={`/report/${scan.id}`} className="btn btn-sm btn-ghost gap-1.5">
                <FileText className="h-4 w-4" /> Open report
              </Link>
            )}
            <button type="button" className="btn btn-sm btn-ghost gap-1.5" onClick={() => exportMarkdown(scan)}>
              <FileDown className="h-4 w-4" /> Markdown
            </button>
            <button type="button" className="btn btn-sm btn-ghost gap-1.5" onClick={() => exportJson(scan)}>
              <Braces className="h-4 w-4" /> JSON
            </button>
            <button type="button" className="btn btn-sm btn-ghost gap-1.5" onClick={() => window.print()}>
              <Printer className="h-4 w-4" /> Print
            </button>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-3 gap-2 sm:grid-cols-6" role="group" aria-label="Filter by severity">
          <button
            type="button"
            onClick={() => setFilter(null)}
            aria-pressed={filter === null}
            className={`rounded-field border px-3 py-2.5 text-left transition-colors ${
              filter === null ? 'border-primary/60 bg-base-300/60' : 'hairline hover:bg-base-300/40'
            }`}
          >
            <span className="block font-mono text-xl font-semibold tabular-nums">{vulns.length}</span>
            <span className="text-xs muted">All</span>
          </button>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              disabled={!counts[s]}
              onClick={() => setFilter(filter === s ? null : s)}
              aria-pressed={filter === s}
              className={`rounded-field border px-3 py-2.5 text-left transition-colors disabled:cursor-default disabled:opacity-45 ${
                filter === s ? `${SEVERITY_META[s].ring} bg-base-300/60` : 'hairline enabled:hover:bg-base-300/40'
              }`}
            >
              <span className={`block font-mono text-xl font-semibold tabular-nums ${counts[s] ? SEVERITY_META[s].text : ''}`}>
                {counts[s]}
              </span>
              <span className="text-xs muted">{SEVERITY_META[s].label}</span>
            </button>
          ))}
        </div>
      </div>

      {scan.warnings?.length > 0 && (
        <div role="status" className="flex gap-3 rounded-box border border-warning/40 bg-warning/10 p-4 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
          <div>
            <p className="font-medium">Some checks did not finish</p>
            <ul className="mt-1 list-disc pl-4 muted">
              {scan.warnings.map((w) => <li key={w}>{w}</li>)}
            </ul>
          </div>
        </div>
      )}

      {vulns.length === 0 ? (
        <div className="surface flex flex-col items-center gap-3 px-6 py-14 text-center">
          <ShieldCheck className="h-8 w-8 text-primary" strokeWidth={1.5} aria-hidden="true" />
          <p className="font-medium">No issues detected</p>
          <p className="max-w-md text-sm muted">
            None of the checks matched. Automated scans cannot prove a system is secure, so keep manual review in your process.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {vulns.length > 8 && (
            <label className="input input-sm no-print mb-2 flex w-full items-center gap-2 sm:max-w-sm">
              <Search className="h-4 w-4 muted" aria-hidden="true" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by title, file or CWE"
                aria-label="Filter findings"
                className="grow"
              />
            </label>
          )}
          {visible.length === 0 && <p className="py-6 text-center text-sm muted">No findings match this filter.</p>}
          {visible.map((v, i) => (
            <VulnerabilityCard key={v.id || i} vuln={v} patch={patches[v.id]} defaultOpen={visible.length === 1} />
          ))}
        </div>
      )}
    </motion.section>
  );
}
