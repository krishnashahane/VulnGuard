import { useState } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { Globe, Loader2 } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import ErrorNotice from '../components/ErrorNotice';
import ScanResults from '../components/ScanResults';
import { scanUrl } from '../lib/api';
import { useScan } from '../hooks/useScan';

const CHECKS = ['Security headers', 'CORS', 'CSRF', 'Information disclosure', 'XSS', 'SQL injection', 'SSRF'];

function validateUrl(raw) {
  const value = raw.trim();
  if (!value) return 'Enter the URL you want to scan.';
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
    if (!['http:', 'https:'].includes(url.protocol)) return 'Only http and https URLs can be scanned.';
    if (!url.hostname.includes('.') && !url.hostname.includes(':')) return 'Enter a full domain, like example.com.';
  } catch {
    return 'That does not look like a valid URL.';
  }
  return null;
}

function Progress({ elapsed, onCancel }) {
  const reduce = useReducedMotion();
  return (
    <div className="surface p-5 sm:p-6" role="status" aria-live="polite">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Loader2 className="h-5 w-5 animate-spin text-primary" aria-hidden="true" />
          <div>
            <p className="font-medium">Running {CHECKS.length} checks in parallel</p>
            <p className="text-sm muted">Usually 10 to 40 seconds. Elapsed: <span className="font-mono tabular-nums">{elapsed}s</span></p>
          </div>
        </div>
        <button type="button" onClick={onCancel} className="btn btn-sm btn-ghost">Cancel</button>
      </div>
      <ul className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {CHECKS.map((check, i) => (
          <li key={check} className="flex items-center gap-2.5 rounded-field border hairline px-3 py-2 text-sm">
            <motion.span
              className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary"
              animate={reduce ? undefined : { opacity: [0.25, 1, 0.25] }}
              transition={{ duration: 1.6, repeat: Infinity, delay: i * 0.15 }}
              aria-hidden="true"
            />
            {check}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function DynamicScan() {
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [touched, setTouched] = useState(false);
  const scan = useScan();

  const urlError = touched ? validateUrl(url) : null;

  const submit = (e) => {
    e.preventDefault();
    setTouched(true);
    if (validateUrl(url) || !consent) return;
    scan.run(scanUrl, url.trim());
  };

  return (
    <div className="page space-y-8 py-10 sm:py-14">
      <PageHeader icon={Globe} title="Dynamic scan">
        Probe a live site for injection, misconfiguration and exposure issues. Private and internal addresses are blocked.
      </PageHeader>

      <form onSubmit={submit} noValidate className="surface space-y-5 p-5 sm:p-6">
        <div className="space-y-2">
          <label htmlFor="target-url" className="text-sm font-medium">Target URL</label>
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              id="target-url"
              type="text"
              inputMode="url"
              autoComplete="url"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="https://staging.yourapp.com/search?q=test"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onBlur={() => url && setTouched(true)}
              aria-invalid={Boolean(urlError)}
              aria-describedby="target-help"
              disabled={scan.running}
              className={`input w-full flex-1 font-mono text-sm ${urlError ? 'input-error' : ''}`}
            />
            <button
              type="submit"
              disabled={scan.running || !consent}
              className="btn btn-primary min-w-36 active:scale-[0.98]"
            >
              {scan.running ? <><Loader2 className="h-4 w-4 animate-spin" /> Scanning</> : 'Start scan'}
            </button>
          </div>
          <p id="target-help" className={`text-xs ${urlError ? 'text-error' : 'muted'}`}>
            {urlError || 'Include query parameters to test them for XSS, SQL injection and SSRF.'}
          </p>
        </div>

        <label className="flex cursor-pointer items-start gap-3 text-sm">
          <input
            type="checkbox"
            className="checkbox checkbox-sm checkbox-primary mt-0.5"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            disabled={scan.running}
          />
          <span>I own this site or have written permission to test it.</span>
        </label>
      </form>

      <ErrorNotice>{scan.error}</ErrorNotice>
      {scan.running && <Progress elapsed={scan.elapsed} onCancel={scan.cancel} />}
      {scan.result && <ScanResults scan={scan.result} showReportLink scrollIntoView />}
    </div>
  );
}
