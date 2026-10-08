import { useSyncExternalStore } from 'react';

const KEY = 'vulnguard:theme';
export const THEMES = { dark: 'vulnguard', light: 'vulnguard-light' };

const listeners = new Set();
let mode = null;

function initialMode() {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === 'dark' || saved === 'light') return saved;
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function apply(next) {
  mode = next;
  document.documentElement.setAttribute('data-theme', THEMES[next]);
  listeners.forEach((fn) => fn());
}

export function applyInitialTheme() {
  apply(initialMode());
}

export function toggleTheme() {
  const next = mode === 'dark' ? 'light' : 'dark';
  try {
    localStorage.setItem(KEY, next);
  } catch {
    /* theme still applies for this session */
  }
  apply(next);
}

const subscribe = (fn) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};

export function useTheme() {
  const current = useSyncExternalStore(subscribe, () => mode ?? 'dark', () => 'dark');
  return { mode: current, toggle: toggleTheme };
}
