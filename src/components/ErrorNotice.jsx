import { AlertCircle } from 'lucide-react';

export default function ErrorNotice({ children }) {
  if (!children) return null;
  return (
    <div role="alert" className="flex gap-3 rounded-box border border-error/40 bg-error/10 p-4 text-sm">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-error" aria-hidden="true" />
      <p>{children}</p>
    </div>
  );
}
