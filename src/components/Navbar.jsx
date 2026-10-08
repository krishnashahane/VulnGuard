import { useEffect, useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import { AnimatePresence, motion } from 'motion/react';
import { Menu, Moon, ShieldCheck, Sun, X } from 'lucide-react';
import { useTheme } from '../lib/theme';

const NAV_LINKS = [
  { name: 'Dashboard', path: '/' },
  { name: 'Dynamic Scan', path: '/scan/dynamic' },
  { name: 'Static Scan', path: '/scan/static' },
];

function linkClass({ isActive }) {
  return `rounded-field px-3 py-2 text-sm font-medium transition-colors ${
    isActive ? 'bg-base-300 text-base-content' : 'muted hover:text-base-content hover:bg-base-300/60'
  }`;
}

export default function Navbar() {
  const [open, setOpen] = useState(false);
  const { mode, toggle } = useTheme();
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  return (
    <header className="no-print sticky top-0 z-40 border-b hairline bg-base-100/80 backdrop-blur-md">
      <nav className="page flex h-16 items-center justify-between gap-4" aria-label="Main">
        <Link to="/" className="flex items-center gap-2 rounded-field" onClick={() => setOpen(false)}>
          <ShieldCheck className="h-6 w-6 text-primary" strokeWidth={1.75} aria-hidden="true" />
          <span className="font-mono text-[17px] font-semibold tracking-tight">VulnGuard</span>
        </Link>

        <div className="hidden items-center gap-1 md:flex">
          {NAV_LINKS.map((link) => (
            <NavLink key={link.path} to={link.path} end={link.path === '/'} className={linkClass}>
              {link.name}
            </NavLink>
          ))}
        </div>

        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={toggle}
            className="btn btn-ghost btn-sm btn-square"
            aria-label={mode === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {mode === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="btn btn-ghost btn-sm btn-square md:hidden"
            aria-expanded={open}
            aria-controls="mobile-menu"
            aria-label={open ? 'Close menu' : 'Open menu'}
          >
            {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </nav>

      <AnimatePresence>
        {open && (
          <motion.div
            id="mobile-menu"
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="border-t hairline bg-base-100 md:hidden"
          >
            <div className="page flex flex-col gap-1 py-3">
              {NAV_LINKS.map((link) => (
                <NavLink
                  key={link.path}
                  to={link.path}
                  end={link.path === '/'}
                  className={linkClass}
                  onClick={() => setOpen(false)}
                >
                  {link.name}
                </NavLink>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
