import { useCallback, useEffect, useRef, useState } from 'react';
import { saveScan } from '../lib/history';

/** Runs one scan at a time, with cancellation, elapsed time and history persistence. */
export function useScan() {
  const [state, setState] = useState({ status: 'idle', result: null, error: null });
  const [elapsed, setElapsed] = useState(0);
  const controller = useRef(null);

  useEffect(() => () => controller.current?.abort(), []);

  useEffect(() => {
    if (state.status !== 'running') return;
    const start = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 1000);
    return () => clearInterval(id);
  }, [state.status]);

  const run = useCallback(
    async (runner, ...args) => {
      controller.current?.abort();
      const ctrl = new AbortController();
      controller.current = ctrl;
      setElapsed(0);
      setState({ status: 'running', result: null, error: null });
      try {
        const result = await runner(...args, { signal: ctrl.signal });
        if (ctrl.signal.aborted) return;
        saveScan(result);
        setState({ status: 'done', result, error: null });
      } catch (err) {
        if (ctrl.signal.aborted) return;
        setState({ status: 'error', result: null, error: err.message || 'Something went wrong.' });
      }
    },
    [],
  );

  const cancel = useCallback(() => {
    controller.current?.abort();
    setState({ status: 'idle', result: null, error: null });
  }, []);

  return { ...state, elapsed, run, cancel, running: state.status === 'running' };
}
