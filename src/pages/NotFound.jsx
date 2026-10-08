import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="page flex flex-col items-start gap-4 py-24">
      <p className="font-mono text-sm text-primary">404</p>
      <h1 className="text-3xl font-semibold tracking-tight">This page does not exist.</h1>
      <p className="muted">The link may be broken or the page was moved.</p>
      <Link to="/" className="btn btn-primary btn-sm mt-2">Back to dashboard</Link>
    </div>
  );
}
