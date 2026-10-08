import { useEffect, useRef, useState } from 'react';
import { Check, Copy, ExternalLink, Wrench } from 'lucide-react';

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef();

  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <button type="button" onClick={copy} className="btn btn-ghost btn-xs gap-1 font-normal" aria-live="polite">
      {copied ? <Check className="h-3.5 w-3.5 text-primary" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

function CodePane({ label, code, tone }) {
  const marker = tone === 'bad' ? '-' : '+';
  const color = tone === 'bad' ? 'text-sev-critical' : 'text-primary';
  return (
    <div className="min-w-0">
      <div className="mb-1.5 flex items-center justify-between">
        <span className={`font-mono text-xs ${color}`}>{label}</span>
        {tone === 'good' && <CopyButton text={code} />}
      </div>
      <pre className="code-block whitespace-pre">
        {code.split('\n').map((line, i) => (
          <div key={i} className="flex gap-3">
            <span className={`select-none ${color} opacity-70`} aria-hidden="true">{marker}</span>
            <code className="min-w-0">{line || ' '}</code>
          </div>
        ))}
      </pre>
    </div>
  );
}

function isSafeLink(ref) {
  try {
    return ['https:', 'http:'].includes(new URL(ref).protocol);
  } catch {
    return false;
  }
}

export default function PatchSuggestion({ patch }) {
  if (!patch) return null;
  // Reports can be imported from files, so never trust link targets
  const references = (patch.references || []).filter((r) => typeof r === 'string' && isSafeLink(r));

  return (
    <section className="@container space-y-4 border-t hairline pt-5" aria-label="Suggested fix">
      <div className="flex items-start gap-2.5">
        <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
        <div className="space-y-1">
          <h4 className="font-medium">{patch.title}</h4>
          {patch.description && <p className="max-w-[70ch] text-sm leading-relaxed muted">{patch.description}</p>}
        </div>
      </div>

      {(patch.original_code || patch.patched_code) && (
        <div className="grid gap-4 @2xl:grid-cols-2">
          {patch.original_code && <CodePane label="Vulnerable pattern" code={patch.original_code} tone="bad" />}
          {patch.patched_code && <CodePane label="Patched" code={patch.patched_code} tone="good" />}
        </div>
      )}

      {references.length > 0 && (
        <ul className="flex flex-wrap gap-x-5 gap-y-1.5">
          {references.map((ref) => {
            const u = new URL(ref);
            const label = `${u.hostname.replace('www.', '')}${u.pathname.replace(/\/$/, '')}`;
            return (
              <li key={ref} className="min-w-0">
                <a
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="link link-hover inline-flex max-w-full items-center gap-1 text-xs muted hover:text-base-content"
                >
                  <ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" />
                  <span className="truncate">{label}</span>
                </a>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
