import { lazy, Suspense, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'motion/react';
import { ArrowRight, Code2, FileUp, FolderGit2, Globe, Trash2 } from 'lucide-react';
import VulnerabilityCard from '../components/VulnerabilityCard';
import { clearScans, importScan, removeScan, useScanHistory } from '../lib/history';
import { SEVERITY_META, countBySeverity } from '../lib/severity';
import { useTheme } from '../lib/theme';

const Particles = lazy(() => import('../components/Particles'));

const EXAMPLE_FINDING = {
  id: 'example',
  severity: 'CRITICAL',
  title: 'SQL query built with f-string',
  owasp_category: 'A03:2021 - Injection',
  cwe_id: 'CWE-89',
  location: 'app/users.py:42',
  evidence: `query = f"SELECT * FROM users WHERE name = '{username}'"`,
};

const EXAMPLE_PATCH = {
  title: 'Use parameterized queries',
  original_code: `query = f"SELECT * FROM users WHERE name = '{username}'"\ncursor.execute(query)`,
  patched_code: `query = "SELECT * FROM users WHERE name = %s"\ncursor.execute(query, (username,))`,
  references: [],
};

const LIVE_CHECKS = [
  'Reflected XSS in parameters and forms',
  'Error and time-based SQL injection',
  'Missing CSRF tokens, SameSite cookies',
  'Security headers and HTTPS',
  'CORS origin reflection and wildcards',
  'SSRF through URL parameters',
  'Exposed .env, .git and backups',
];

const CODE_CHECKS = [
  'Hardcoded keys, tokens and passwords',
  'SQL, shell and eval injection sinks',
  'Weak password hashing, permissive CORS',
  'Debug mode and insecure cookie flags',
  'Dependencies with known CVEs (OSV.dev)',
];

const ease = [0.16, 1, 0.3, 1];

function Hero() {
  const reduce = useReducedMotion();
  const { mode } = useTheme();
  const rise = (delay) =>
    reduce ? {} : { initial: { opacity: 0, y: 16 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.6, delay, ease } };

  return (
    <section className="relative overflow-hidden border-b hairline">
      <div className="grid-backdrop absolute inset-0" aria-hidden="true" />
      <Suspense fallback={null}>
        <Particles
          className="absolute inset-0"
          colors={mode === 'dark' ? ['#4ade80', '#64748b'] : ['#15803d', '#94a3b8']}
          opacity={mode === 'dark' ? 0.75 : 0.5}
          count={240}
        />
      </Suspense>

      <div className="page relative grid items-center gap-12 py-16 md:py-20 lg:grid-cols-[1.05fr_1fr] lg:gap-14 lg:py-24">
        <div className="max-w-xl">
          <motion.h1
            {...rise(0)}
            className="text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl lg:text-[3.5rem]"
          >
            Find the flaw before someone else does.
          </motion.h1>
          <motion.p {...rise(0.08)} className="mt-5 max-w-[46ch] text-lg leading-relaxed muted">
            Probe live sites and source code for OWASP Top 10 issues, then get a fix you can paste.
          </motion.p>
          <motion.div {...rise(0.16)} className="mt-8 flex flex-wrap gap-3">
            <Link to="/scan/dynamic" className="btn btn-primary gap-2 active:scale-[0.98]">
              <Globe className="h-4 w-4" /> Scan a URL
            </Link>
            <Link to="/scan/static" className="btn btn-ghost gap-2 border hairline active:scale-[0.98]">
              <Code2 className="h-4 w-4" /> Analyze code
            </Link>
          </motion.div>
        </div>

        <motion.div
          initial={reduce ? false : { opacity: 0, y: 24, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.8, delay: 0.2, ease }}
          className="relative"
        >
          <p className="mb-2 text-xs muted">Example finding</p>
          <div className="pointer-events-none select-none shadow-2xl shadow-black/20" aria-hidden="true" inert>
            <VulnerabilityCard vuln={EXAMPLE_FINDING} patch={EXAMPLE_PATCH} defaultOpen />
          </div>
        </motion.div>
      </div>
    </section>
  );
}

function Coverage() {
  const reduce = useReducedMotion();
  const reveal = (i) =>
    reduce
      ? {}
      : {
          initial: { opacity: 0, y: 20 },
          whileInView: { opacity: 1, y: 0 },
          viewport: { once: true, amount: 0.3 },
          transition: { duration: 0.6, delay: i * 0.08, ease },
        };

  return (
    <section className="page py-16 md:py-20">
      <h2 className="max-w-2xl text-2xl font-semibold tracking-tight sm:text-3xl">Two ways in, one report out.</h2>
      <p className="mt-3 max-w-[60ch] muted">
        Every finding maps to an OWASP category and CWE, with a remediation pattern attached.
      </p>

      <div className="mt-10 grid gap-4 lg:grid-cols-[7fr_5fr]">
        <motion.div {...reveal(0)} className="surface relative overflow-hidden p-6 sm:p-8">
          <div className="flex items-center gap-2.5">
            <Globe className="h-5 w-5 text-primary" aria-hidden="true" />
            <h3 className="font-medium">Dynamic scan</h3>
          </div>
          <p className="mt-2 text-sm muted">Sends safe probes to a running site and reads how it responds.</p>
          <ul className="mt-6 grid gap-x-6 gap-y-2.5 text-sm sm:grid-cols-2">
            {LIVE_CHECKS.map((c) => (
              <li key={c} className="border-l-2 border-primary/50 pl-3">{c}</li>
            ))}
          </ul>
          <Link to="/scan/dynamic" className="link link-hover mt-8 inline-flex items-center gap-1.5 text-sm font-medium text-primary">
            Start a dynamic scan <ArrowRight className="h-4 w-4" />
          </Link>
        </motion.div>

        <motion.div {...reveal(1)} className="relative overflow-hidden rounded-box border border-primary/25 bg-primary/[0.06] p-6 sm:p-8">
          <div className="flex items-center gap-2.5">
            <Code2 className="h-5 w-5 text-primary" aria-hidden="true" />
            <h3 className="font-medium">Static analysis</h3>
          </div>
          <p className="mt-2 text-sm muted">Paste a file, drop a folder or point at a public GitHub repo. Nothing is stored server-side.</p>
          <ul className="mt-6 space-y-2.5 text-sm">
            {CODE_CHECKS.map((c) => (
              <li key={c} className="border-l-2 border-primary/50 pl-3">{c}</li>
            ))}
          </ul>
          <Link to="/scan/static" className="link link-hover mt-8 inline-flex items-center gap-1.5 text-sm font-medium text-primary">
            Analyze code <ArrowRight className="h-4 w-4" />
          </Link>
        </motion.div>
      </div>
    </section>
  );
}

function ImportButton() {
  const input = useRef(null);
  const navigate = useNavigate();
  const [error, setError] = useState(null);

  const onFile = async (file) => {
    if (!file) return;
    setError(null);
    try {
      if (file.size > 10 * 1024 * 1024) throw new Error('Report file is larger than 10 MB.');
      const scan = importScan(JSON.parse(await file.text()));
      navigate(`/report/${scan.id}`);
    } catch (err) {
      setError(err instanceof SyntaxError ? 'That file is not valid JSON.' : err.message);
    }
  };

  return (
    <div className="flex flex-col items-end gap-1">
      <button type="button" className="btn btn-sm btn-ghost gap-1.5 border hairline" onClick={() => input.current?.click()}>
        <FileUp className="h-4 w-4" /> Import report
      </button>
      <input ref={input} type="file" accept="application/json,.json" className="hidden"
        onChange={(e) => { onFile(e.target.files?.[0]); e.target.value = ''; }} />
      {error && <p role="alert" className="text-xs text-error">{error}</p>}
    </div>
  );
}

const TYPE_ICONS = { dynamic: [Globe, 'Dynamic scan'], repo: [FolderGit2, 'Repository scan'], static: [Code2, 'Static analysis'] };

function RecentScans() {
  const scans = useScanHistory();
  const totals = scans.reduce(
    (acc, s) => {
      const c = countBySeverity(s.vulnerabilities);
      acc.findings += s.vulnerabilities?.length ?? 0;
      acc.critical += c.CRITICAL + c.HIGH;
      return acc;
    },
    { findings: 0, critical: 0 },
  );

  return (
    <section className="border-t hairline bg-base-200/50">
      <div className="page py-16 md:py-20">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold tracking-tight">Recent scans</h2>
            <p className="mt-1 text-sm muted">Stored in this browser only. Export JSON to move a report between devices.</p>
          </div>
          <ImportButton />
          {scans.length > 0 && (
            <dl className="flex gap-8 text-sm">
              <div>
                <dt className="muted">Scans</dt>
                <dd className="font-mono text-2xl font-semibold tabular-nums">{scans.length}</dd>
              </div>
              <div>
                <dt className="muted">Findings</dt>
                <dd className="font-mono text-2xl font-semibold tabular-nums">{totals.findings}</dd>
              </div>
              <div>
                <dt className="muted">High or worse</dt>
                <dd className={`font-mono text-2xl font-semibold tabular-nums ${totals.critical ? 'text-sev-critical' : ''}`}>
                  {totals.critical}
                </dd>
              </div>
            </dl>
          )}
        </div>

        {scans.length === 0 ? (
          <div className="mt-8 rounded-box border border-dashed hairline px-6 py-12 text-center">
            <p className="font-medium">No scans yet</p>
            <p className="mx-auto mt-1 max-w-sm text-sm muted">Results appear here after your first scan so you can reopen and export them.</p>
            <Link to="/scan/static" className="btn btn-sm btn-primary mt-5">Try static analysis</Link>
          </div>
        ) : (
          <>
            <ul className="mt-8 divide-y hairline overflow-hidden rounded-box border hairline bg-base-100">
              {scans.slice(0, 8).map((s) => {
                const c = countBySeverity(s.vulnerabilities);
                return (
                  <li key={s.id} className="group flex items-center gap-3 px-4 py-3 transition-colors hover:bg-base-300/40 sm:px-5">
                    {(() => {
                      const [Icon, label] = TYPE_ICONS[s.scan_type] || TYPE_ICONS.static;
                      return <Icon className="h-4 w-4 shrink-0 muted" aria-label={label} />;
                    })()}
                    <Link to={`/report/${s.id}`} className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-sm">{s.target}</span>
                      <span className="text-xs muted">{new Date(s.completed_at || s.started_at).toLocaleString()}</span>
                    </Link>
                    <span className="hidden gap-3 font-mono text-xs tabular-nums sm:flex">
                      {['CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                        <span key={sev} className={c[sev] ? SEVERITY_META[sev].text : 'muted opacity-50'} title={SEVERITY_META[sev].label}>
                          {c[sev]} {sev[0]}
                        </span>
                      ))}
                    </span>
                    <button
                      type="button"
                      onClick={() => removeScan(s.id)}
                      className="btn btn-ghost btn-xs btn-square opacity-60 hover:opacity-100"
                      aria-label={`Remove scan of ${s.target}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </li>
                );
              })}
            </ul>
            <button type="button" onClick={clearScans} className="btn btn-ghost btn-xs mt-3 muted">
              Clear history
            </button>
          </>
        )}
      </div>
    </section>
  );
}

export default function Dashboard() {
  return (
    <>
      <Hero />
      <Coverage />
      <RecentScans />
    </>
  );
}
