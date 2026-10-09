import { CircleCheck, CircleDashed, CircleX, Clock } from 'lucide-react';

const STATUS = {
  passed: { Icon: CircleCheck, className: 'text-primary', label: 'Passed' },
  failed: { Icon: CircleX, className: 'text-sev-critical', label: 'Failed' },
  not_tested: { Icon: CircleDashed, className: 'muted', label: 'Not tested' },
  skipped: { Icon: Clock, className: 'text-warning', label: 'Timed out' },
  error: { Icon: Clock, className: 'text-warning', label: 'Incomplete' },
};

export default function CheckList({ checks }) {
  const tested = checks.filter((c) => c.status === 'passed' || c.status === 'failed');
  const failed = tested.filter((c) => c.status === 'failed').length;
  const pct = tested.length ? Math.round((failed / tested.length) * 100) : 0;
  const untested = checks.some((c) => c.status === 'not_tested');

  return (
    <div className="mt-6 border-t hairline pt-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-sm font-medium">Checks</h3>
        <p className="text-sm muted">
          <span className={`font-mono tabular-nums ${failed ? 'text-sev-critical' : 'text-primary'}`}>{failed}</span>
          {' of '}
          <span className="font-mono tabular-nums">{tested.length}</span> tested checks failed
          {tested.length > 0 && <span className="font-mono tabular-nums"> ({pct}%)</span>}
        </p>
      </div>
      <ul className="mt-3 grid gap-x-6 sm:grid-cols-2">
        {checks.map((c) => {
          const { Icon, className, label } = STATUS[c.status] || STATUS.error;
          return (
            <li key={c.name} className="flex items-center gap-3 border-b hairline py-2.5 text-sm last:border-b-0 sm:[&:nth-last-child(2):nth-child(odd)]:border-b-0">
              <Icon className={`h-4 w-4 shrink-0 ${className}`} aria-hidden="true" />
              <span className="flex-1">{c.name}</span>
              <span className={`text-xs ${c.status === 'failed' ? 'text-base-content' : 'muted'}`}>
                <span className="sr-only">{label}: </span>
                {c.detail}
              </span>
            </li>
          );
        })}
      </ul>
      {untested && (
        <p className="mt-3 text-xs muted">
          Injection checks need input. Scan a URL with query parameters, like <code className="font-mono">/search?q=test</code>, to test them.
        </p>
      )}
    </div>
  );
}
