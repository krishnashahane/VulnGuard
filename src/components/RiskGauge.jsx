import { motion, useReducedMotion } from 'motion/react';
import { SEVERITY_META } from '../lib/severity';

const R = 42;
const C = 2 * Math.PI * R;

export default function RiskGauge({ score, tone }) {
  const reduce = useReducedMotion();
  const color = tone ? SEVERITY_META[tone].text : 'text-primary';

  return (
    <div className={`relative h-20 w-20 shrink-0 sm:h-28 sm:w-28 ${color}`} role="img" aria-label={`Risk score ${score} percent`}>
      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="50" cy="50" r={R} fill="none" strokeWidth="7" className="stroke-base-300" />
        <motion.circle
          cx="50"
          cy="50"
          r={R}
          fill="none"
          stroke="currentColor"
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={C}
          initial={{ strokeDashoffset: reduce ? C * (1 - score / 100) : C }}
          animate={{ strokeDashoffset: C * (1 - score / 100) }}
          transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-xl font-semibold sm:text-2xl tabular-nums text-base-content">
          {score}
          <span className="text-sm muted sm:text-base">%</span>
        </span>
        <span className="text-[10px] uppercase tracking-wide muted sm:text-[11px]">risk</span>
      </div>
    </div>
  );
}
