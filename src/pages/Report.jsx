import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, FileSearch } from 'lucide-react';
import ScanResults from '../components/ScanResults';
import { fetchScan } from '../lib/api';
import { getScan, saveScan, useScanHistory } from '../lib/history';

function Skeleton() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading report">
      <div className="surface space-y-4 p-6">
        <div className="skeleton h-4 w-28" />
        <div className="skeleton h-6 w-2/3" />
        <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
          {Array.from({ length: 6 }, (_, i) => <div key={i} className="skeleton h-16" />)}
        </div>
      </div>
      {Array.from({ length: 3 }, (_, i) => <div key={i} className="skeleton h-14 w-full" />)}
    </div>
  );
}

export default function Report() {
  const { id } = useParams();
  const history = useScanHistory();
  const local = history.find((s) => s.id === id) ?? null;
  // Remote lookup result, keyed by id so a stale response never shows under a new URL
  const [remote, setRemote] = useState({ id: null, missing: false });

  useEffect(() => {
    if (getScan(id)) return;
    const ctrl = new AbortController();
    fetchScan(id, { signal: ctrl.signal })
      .then((scan) => saveScan(scan))
      .catch(() => !ctrl.signal.aborted && setRemote({ id, missing: true }));
    return () => ctrl.abort();
  }, [id]);

  const state = local
    ? { status: 'ready', scan: local }
    : { status: remote.id === id && remote.missing ? 'missing' : 'loading', scan: null };

  return (
    <div className="page space-y-6 py-10 sm:py-14">
      <div className="no-print flex items-center justify-between">
        <Link to="/" className="btn btn-ghost btn-sm -ml-3 gap-1.5">
          <ArrowLeft className="h-4 w-4" /> Dashboard
        </Link>
        <span className="truncate pl-4 font-mono text-xs muted">Report {id.slice(0, 8)}</span>
      </div>

      {state.status === 'loading' && <Skeleton />}
      {state.status === 'ready' && <ScanResults scan={state.scan} />}
      {state.status === 'missing' && (
        <div className="surface flex flex-col items-center gap-3 px-6 py-16 text-center">
          <FileSearch className="h-8 w-8 muted" strokeWidth={1.5} aria-hidden="true" />
          <h1 className="text-lg font-medium">Report not found</h1>
          <p className="max-w-md text-sm muted">
            Reports are kept in the browser that ran the scan. This one may have been cleared or was created on another device.
          </p>
          <div className="mt-2 flex gap-2">
            <Link to="/scan/dynamic" className="btn btn-sm btn-primary">New dynamic scan</Link>
            <Link to="/scan/static" className="btn btn-sm btn-ghost border hairline">New static scan</Link>
          </div>
        </div>
      )}
    </div>
  );
}
