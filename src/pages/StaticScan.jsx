import { useRef, useState } from 'react';
import { motion } from 'motion/react';
import { ClipboardPaste, Code2, FileStack, FolderGit2, FolderOpen, Loader2, Upload, X } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import ErrorNotice from '../components/ErrorNotice';
import ScanResults from '../components/ScanResults';
import { scanCode, scanFiles, scanRepo } from '../lib/api';
import { useScan } from '../hooks/useScan';

const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 50;
const SOURCE_EXT = /\.(py|jsx?|tsx?|mjs|cjs|php|java|kt|rb|go|cs|rs|swift|sh|sql|html?|vue|svelte|json|ya?ml|toml|ini|cfg|conf|xml|properties|tf|txt)$/i;
const SKIP_DIR = /(^|\/)(node_modules|\.git|vendor|dist|build|\.next|__pycache__|\.venv|venv|coverage|target)\//;

const MODES = [
  { id: 'paste', label: 'Paste code', icon: ClipboardPaste },
  { id: 'files', label: 'Files or folder', icon: FileStack },
  { id: 'repo', label: 'GitHub repo', icon: FolderGit2 },
];

const EXAMPLE = `import os
import hashlib
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "changeme"
DATABASE_URL = "postgres://admin:hunter2@db.internal:5432/prod"

@app.route("/user")
def user():
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query)

@app.route("/ping")
def ping():
    os.system(f"ping -c 1 {request.args['host']}")

def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True)
`;

const byteLength = (s) => new TextEncoder().encode(s).length;
const kb = (n) => `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;

function readText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
    reader.readAsText(file);
  });
}

function PasteMode({ onSubmit, running, setError }) {
  const [code, setCode] = useState('');
  const [filename, setFilename] = useState('snippet.py');
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef(null);
  const size = byteLength(code);
  const tooBig = size > MAX_FILE_BYTES;

  const loadFile = async (file) => {
    if (!file) return;
    setError(null);
    if (file.size > MAX_FILE_BYTES) return setError(`${file.name} is ${kb(file.size)}. The limit is 512 KB.`);
    try {
      const text = await readText(file);
      if (text.includes('\u0000')) return setError(`${file.name} looks like a binary file.`);
      setFilename(file.name);
      setCode(text);
    } catch (err) {
      setError(err.message);
    }
  };

  const submit = (e) => {
    e?.preventDefault();
    setError(null);
    if (!code.trim()) return setError('Paste some code or upload a file first.');
    if (tooBig) return setError('Input is larger than 512 KB. Use the files mode to split it.');
    onSubmit(scanCode, code, filename.trim() || 'snippet');
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="space-y-2 sm:w-64">
          <label htmlFor="filename" className="text-sm font-medium">File name</label>
          <input id="filename" type="text" value={filename} maxLength={255} spellCheck={false}
            onChange={(e) => setFilename(e.target.value)} className="input input-sm w-full font-mono" />
        </div>
        <div className="flex flex-wrap gap-2 sm:ml-auto">
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => { setCode(EXAMPLE); setFilename('app.py'); setError(null); }}>
            Load example
          </button>
          {code && <button type="button" className="btn btn-sm btn-ghost" onClick={() => setCode('')}>Clear</button>}
          <button type="button" className="btn btn-sm btn-ghost gap-1.5 border hairline" onClick={() => fileInput.current?.click()}>
            <Upload className="h-4 w-4" /> Open file
          </button>
          <input ref={fileInput} type="file" className="hidden" onChange={(e) => { loadFile(e.target.files?.[0]); e.target.value = ''; }} />
        </div>
      </div>

      <div className="space-y-2">
        <label htmlFor="source" className="text-sm font-medium">Source code</label>
        <div
          className="relative"
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); loadFile(e.dataTransfer.files?.[0]); }}
        >
          <textarea
            id="source" rows={16} value={code} spellCheck={false}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => (e.metaKey || e.ctrlKey) && e.key === 'Enter' && submit(e)}
            placeholder="Paste code here, or drop a file onto this box."
            aria-describedby="source-help"
            className={`textarea min-h-72 w-full resize-y font-mono text-[13px] leading-relaxed ${tooBig ? 'textarea-error' : ''}`}
          />
          {dragging && (
            <div className="pointer-events-none absolute inset-0 grid place-items-center rounded-field border-2 border-dashed border-primary bg-base-100/85 text-sm font-medium">
              Drop to load file
            </div>
          )}
        </div>
        <div id="source-help" className="flex flex-wrap items-center justify-between gap-2 text-xs muted">
          <span>Paste requirements.txt or package.json to check dependencies for known CVEs.</span>
          <span className={`font-mono tabular-nums ${tooBig ? 'text-error' : ''}`}>{kb(size)} / 512 KB</span>
        </div>
      </div>

      <div className="flex items-center justify-end gap-3">
        <span className="hidden text-xs muted sm:inline"><kbd className="kbd kbd-xs">Ctrl</kbd> + <kbd className="kbd kbd-xs">Enter</kbd></span>
        <SubmitButton running={running} />
      </div>
    </form>
  );
}

function FilesMode({ onSubmit, running, setError }) {
  const [files, setFiles] = useState([]);
  const [dragging, setDragging] = useState(false);
  const [note, setNote] = useState(null);
  const fileInput = useRef(null);
  const folderInput = useRef(null);
  const total = files.reduce((n, f) => n + f.size, 0);

  const addFiles = async (list) => {
    setError(null);
    const incoming = Array.from(list || []);
    let skipped = 0;
    const next = [...files];
    for (const file of incoming) {
      const path = file.webkitRelativePath || file.name;
      if (SKIP_DIR.test(path) || (!SOURCE_EXT.test(file.name) && !file.name.startsWith('.env')) || file.size > MAX_FILE_BYTES) {
        skipped++;
        continue;
      }
      if (next.length >= MAX_FILES || next.reduce((n, f) => n + f.size, 0) + file.size > MAX_TOTAL_BYTES) {
        skipped++;
        continue;
      }
      if (next.some((f) => f.path === path)) continue;
      try {
        const content = await readText(file);
        if (content.includes('\u0000')) { skipped++; continue; }
        next.push({ path, size: file.size, content });
      } catch {
        skipped++;
      }
    }
    setFiles(next);
    setNote(skipped ? `${skipped} file${skipped === 1 ? '' : 's'} skipped (unsupported type, dependency folder, or over the size limits).` : null);
  };

  const submit = (e) => {
    e.preventDefault();
    if (!files.length) return setError('Add at least one file.');
    onSubmit(scanFiles, files.map((f) => ({ filename: f.path, content: f.content })));
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files); }}
        className={`flex flex-col items-center gap-3 rounded-box border-2 border-dashed px-6 py-10 text-center transition-colors ${dragging ? 'border-primary bg-primary/5' : 'hairline'}`}
      >
        <FileStack className="h-7 w-7 muted" strokeWidth={1.5} aria-hidden="true" />
        <p className="font-medium">Drop source files here</p>
        <p className="text-sm muted">Up to {MAX_FILES} files, 2 MB total. Manifests are checked against OSV.dev.</p>
        <div className="mt-1 flex flex-wrap justify-center gap-2">
          <button type="button" className="btn btn-sm btn-ghost gap-1.5 border hairline" onClick={() => fileInput.current?.click()}>
            <Upload className="h-4 w-4" /> Choose files
          </button>
          <button type="button" className="btn btn-sm btn-ghost gap-1.5 border hairline" onClick={() => folderInput.current?.click()}>
            <FolderOpen className="h-4 w-4" /> Choose folder
          </button>
        </div>
        <input ref={fileInput} type="file" multiple className="hidden" onChange={(e) => { addFiles(e.target.files); e.target.value = ''; }} />
        <input ref={folderInput} type="file" webkitdirectory="" directory="" multiple className="hidden" onChange={(e) => { addFiles(e.target.files); e.target.value = ''; }} />
      </div>

      {note && <p className="text-xs muted">{note}</p>}

      {files.length > 0 && (
        <div>
          <div className="mb-2 flex items-center justify-between text-xs muted">
            <span>{files.length} file{files.length === 1 ? '' : 's'}, {kb(total)}</span>
            <button type="button" className="btn btn-ghost btn-xs" onClick={() => setFiles([])}>Remove all</button>
          </div>
          <ul className="max-h-64 divide-y hairline overflow-y-auto rounded-field border hairline">
            {files.map((f) => (
              <li key={f.path} className="flex items-center gap-3 px-3 py-1.5 text-sm">
                <span className="min-w-0 flex-1 truncate font-mono text-[13px]">{f.path}</span>
                <span className="shrink-0 font-mono text-xs muted tabular-nums">{kb(f.size)}</span>
                <button type="button" className="btn btn-ghost btn-xs btn-square" aria-label={`Remove ${f.path}`}
                  onClick={() => setFiles(files.filter((x) => x.path !== f.path))}>
                  <X className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex justify-end"><SubmitButton running={running} disabled={!files.length} /></div>
    </form>
  );
}

function RepoMode({ onSubmit, running, setError }) {
  const [repo, setRepo] = useState('');
  const submit = (e) => {
    e.preventDefault();
    const value = repo.trim();
    if (!/^(https?:\/\/)?(www\.)?github\.com\/[\w.-]+\/[\w.-]+|^[\w-]+\/[\w.-]+$/.test(value)) {
      return setError('Enter a public GitHub repository, like github.com/owner/repo.');
    }
    setError(null);
    onSubmit(scanRepo, value);
  };

  return (
    <form onSubmit={submit} className="space-y-2">
      <label htmlFor="repo" className="text-sm font-medium">Repository</label>
      <div className="flex flex-col gap-3 sm:flex-row">
        <input
          id="repo" type="text" inputMode="url" spellCheck={false} autoCapitalize="off"
          placeholder="github.com/owner/repo or github.com/owner/repo/tree/branch"
          value={repo} onChange={(e) => setRepo(e.target.value)} disabled={running}
          aria-describedby="repo-help" className="input w-full flex-1 font-mono text-sm"
        />
        <SubmitButton running={running} label="Scan repo" />
      </div>
      <p id="repo-help" className="text-xs muted">
        Public repositories only, up to 20 MB. Dependency folders and binaries are skipped.{' '}
        <button type="button" className="link link-hover text-primary" onClick={() => setRepo('github.com/Saumya039/PBL3')}>
          Try an example
        </button>
      </p>
    </form>
  );
}

function SubmitButton({ running, disabled = false, label = 'Analyze' }) {
  return (
    <button type="submit" disabled={running || disabled} className="btn btn-primary min-w-32 active:scale-[0.98]">
      {running ? <><Loader2 className="h-4 w-4 animate-spin" /> Analyzing</> : label}
    </button>
  );
}

export default function StaticScan() {
  const [mode, setMode] = useState('paste');
  const [localError, setLocalError] = useState(null);
  const scan = useScan();
  const props = { onSubmit: scan.run, running: scan.running, setError: setLocalError };

  return (
    <div className="page space-y-8 py-10 sm:py-14">
      <PageHeader icon={Code2} title="Static analysis">
        Find hardcoded secrets, injection sinks, insecure configuration and dependencies with known CVEs.
      </PageHeader>

      <div className="surface p-5 sm:p-6">
        <div role="tablist" aria-label="Input type" className="mb-6 flex gap-1 overflow-x-auto rounded-field bg-base-100 p-1">
          {MODES.map(({ id, label, icon: Icon }) => (
            <button
              key={id} type="button" role="tab" aria-selected={mode === id}
              onClick={() => { setMode(id); setLocalError(null); }}
              className={`relative flex flex-1 items-center justify-center gap-2 whitespace-nowrap rounded-field px-3 py-2 text-sm font-medium transition-colors ${mode === id ? '' : 'muted hover:text-base-content'}`}
            >
              {mode === id && (
                <motion.span layoutId="mode-pill" className="absolute inset-0 rounded-field bg-base-300" transition={{ type: 'spring', stiffness: 400, damping: 34 }} />
              )}
              <Icon className="relative h-4 w-4" aria-hidden="true" />
              <span className="relative">{label}</span>
            </button>
          ))}
        </div>

        <div role="tabpanel">
          {mode === 'paste' && <PasteMode {...props} />}
          {mode === 'files' && <FilesMode {...props} />}
          {mode === 'repo' && <RepoMode {...props} />}
        </div>
      </div>

      {scan.running && (
        <p className="text-sm muted" role="status">
          Analyzing{mode === 'repo' ? ' repository' : ''}... <span className="font-mono tabular-nums">{scan.elapsed}s</span>
          <button type="button" className="btn btn-ghost btn-xs ml-2" onClick={scan.cancel}>Cancel</button>
        </p>
      )}
      <ErrorNotice>{localError || scan.error}</ErrorNotice>
      {scan.result && <ScanResults scan={scan.result} showReportLink scrollIntoView />}
    </div>
  );
}
