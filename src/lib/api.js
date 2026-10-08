const API_BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '');

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, { body, timeout = 90_000, signal } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException('timeout', 'TimeoutError')), timeout);
  signal?.addEventListener('abort', () => controller.abort(signal.reason), { once: true });

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    if (signal?.aborted) throw err;
    if (controller.signal.aborted) throw new ApiError('The scan took too long and was stopped. Try a narrower target.', 408);
    throw new ApiError('Could not reach the VulnGuard API. Check your connection and try again.', 0);
  } finally {
    clearTimeout(timer);
  }

  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(describeError(response.status, data), response.status);
  }
  if (!data) throw new ApiError('The server returned an unreadable response.', response.status);
  return data;
}

function describeError(status, data) {
  const detail = data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail) && detail[0]?.msg) {
    if (detail[0].type === 'string_too_long') return 'Input is too large. The limit is 512 KB per file.';
    if (detail[0].type === 'too_long') return 'Too many files. The limit is 50 per scan.';
    return detail[0].msg;
  }
  if (status === 429) return 'Too many scans in a short time. Wait a minute and try again.';
  if (status === 504) return 'The scan exceeded the server time limit.';
  return `Request failed (HTTP ${status}).`;
}

export const scanUrl = (target, opts) => request('/api/scan/dynamic', { ...opts, body: { target, scan_type: 'dynamic' } });

export const scanCode = (code, filename, opts) =>
  request('/api/scan/static', { ...opts, timeout: 30_000, body: { target: code, filename, scan_type: 'static' } });

export const scanFiles = (files, opts) =>
  request('/api/scan/files', { ...opts, timeout: 45_000, body: { files } });

export const scanRepo = (target, opts) => request('/api/scan/repo', { ...opts, body: { target } });

export const fetchScan = (id, opts) => request(`/api/scan/${encodeURIComponent(id)}`, { ...opts, timeout: 15_000 });
