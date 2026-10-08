import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import Navbar from './Navbar';

export default function Layout({ children }) {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [pathname]);

  return (
    <div className="flex min-h-dvh flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 btn btn-sm btn-primary">
        Skip to content
      </a>
      <Navbar />
      <main id="main" className="flex-1">
        {children}
      </main>
      <footer className="no-print border-t hairline">
        <div className="page flex flex-col gap-2 py-6 text-sm muted sm:flex-row sm:items-center sm:justify-between">
          <p>Only scan systems you own or have written permission to test.</p>
          <p className="font-mono text-xs">VulnGuard. MIT licensed.</p>
        </div>
      </footer>
    </div>
  );
}
