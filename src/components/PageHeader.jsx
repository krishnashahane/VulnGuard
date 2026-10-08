import { motion, useReducedMotion } from 'motion/react';

export default function PageHeader({ icon: Icon, title, children }) {
  const reduce = useReducedMotion();
  return (
    <motion.header
      initial={reduce ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="space-y-2"
    >
      <div className="flex items-center gap-3">
        <Icon className="h-6 w-6 text-primary" strokeWidth={1.75} aria-hidden="true" />
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
      </div>
      <p className="max-w-[62ch] muted">{children}</p>
    </motion.header>
  );
}
