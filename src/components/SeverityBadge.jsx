import { SEVERITY_META, normalizeSeverity } from '../lib/severity';

export default function SeverityBadge({ severity }) {
  const key = normalizeSeverity(severity);
  const meta = SEVERITY_META[key];

  return (
    <span
      className={`inline-flex w-[76px] shrink-0 items-center justify-center rounded-field border px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide ${meta.text} ${meta.ring}`}
    >
      {meta.label}
    </span>
  );
}
