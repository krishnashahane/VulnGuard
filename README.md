# VulnGuard: Automated Vulnerability Scanner + Auto-Patch Suggestor

VulnGuard is a full-stack security testing platform that combines dynamic web application testing (DAST), static code security analysis (SAST), and actionable auto-patch suggestions with visual code diffs.

## Features

- **Dynamic Analysis (DAST)**:
  - Cross-Site Scripting (XSS) detection via query parameters and form injection.
  - SQL Injection (SQLi) checking error-based & time-based blind SQLi.
  - CSRF protection inspection (hidden token presence & SameSite cookie attributes).
  - Security header analysis (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
  - Server-Side Request Forgery (SSRF) checks against private IP ranges and internal metadata endpoints.
  - CORS misconfiguration scanning (reflection, wildcards with credentials, null origins).
  - Information disclosure probing sensitive paths (`.env`, `.git/HEAD`, backups, `robots.txt`).

- **Static Analysis (SAST)**:
  - Hardcoded secrets and credential detection (AWS keys, tokens, passwords, database strings, private keys).
  - Injection pattern detection (SQL concatenation/f-strings, OS command injection `os.system`/`subprocess`, `eval`/`exec`, direct DOM manipulations).
  - Insecure authentication checks (weak hashing algorithms like MD5/SHA1, hardcoded credentials, permissive CORS origins).
  - Security misconfiguration identification (`DEBUG = True`, weak secret keys, permissive host settings, insecure cookie flags).
  - Known-vulnerable dependencies (OWASP A06): `requirements*.txt`, `package.json` and `package-lock.json` are checked against the OSV.dev advisory database, with the minimum safe upgrade for each package.
  - Project scanning: upload many files or a whole folder, or scan a public GitHub repository by URL (fetched in memory, dependency folders and binaries skipped).

- **Auto-Patch Engine**:
  - Automatically pairs detected vulnerabilities with recommended remediation steps.
  - Generates before-and-after code diffs with explanations and official OWASP/CWE references.

- **Interfaces**:
  - **Web app**: React 19 + Vite + Tailwind v4 + daisyUI + Motion. Dark and light themes, fully responsive, severity filters, Markdown/JSON export, print-ready reports, local scan history.
  - **Interactive CLI Tool**: Standalone command-line client with color-coded ANSI terminal outputs and JSON export support.

---

## Architecture Overview

```
├── backend/
│   ├── api/routes.py            # FastAPI endpoints (/api/scan/dynamic|static|files|repo, /api/health)
│   ├── patcher/engine.py        # Remediation & patch generation engine
│   ├── scanner/
│   │   ├── dynamic/             # DAST engines (XSS, SQLi, CSRF, Headers, SSRF, CORS, Info Disclosure)
│   │   ├── static/              # SAST engines (Secrets, Injection, Auth, Config)
│   │   └── models.py            # Pydantic data schemas
│   ├── scanner/dynamic/netguard.py  # Outbound guard: blocks private/internal targets, caps response size
│   └── main.py                  # Server entry point & CORS configuration
├── api/index.py                 # Vercel serverless entry (re-exports backend.main:app)
├── tests/                       # pytest suite (API, scanners, SSRF guard)
├── frontend/
│   ├── src/
│   │   ├── components/          # Reusable cards, badges, diffs, navbar, layout
│   │   ├── pages/               # Dashboard, DynamicScan, StaticScan, Report
│   │   ├── lib/                 # API client, local history, theme, export
│   │   ├── App.jsx              # Client router (code-split pages)
│   │   └── index.css            # daisyUI themes + design tokens
├── cli/
│   └── vulnguard_cli.py         # Full-featured command-line scanner
```

---

## Getting Started

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 2. Backend Setup
From the project root:
```bash
# Install Python dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Start the FastAPI server
uvicorn backend.main:app --port 8000 --reload

# Run the tests
pytest tests -q
```
The API documentation is available at `http://localhost:8000/api/docs`.

### 3. Frontend Setup
From the `frontend/` directory:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

### 4. Running the CLI Tool
The standalone CLI tool interacts directly with the core scanner and auto-patch engine:

```bash
# Scan a live website
py cli/vulnguard_cli.py scan-url https://example.com

# Run static analysis on a source file
py cli/vulnguard_cli.py scan-file path/to/script.py

# Output results as JSON
py cli/vulnguard_cli.py scan-file path/to/script.py --format json

# Filter by minimum severity
py cli/vulnguard_cli.py scan-file path/to/script.py --severity HIGH

# Pipe code via standard input
cat vulnerable_code.py | py cli/vulnguard_cli.py scan-code

# Scan a whole project directory (SAST + dependency CVEs)
py cli/vulnguard_cli.py scan-dir ./my-project

# Scan a public GitHub repository
py cli/vulnguard_cli.py scan-repo github.com/owner/repo

# Scan a local app you own (private addresses are blocked by default)
py cli/vulnguard_cli.py scan-url http://localhost:3000 --allow-private
```

---

## Security model

The dynamic scanner fetches user-supplied URLs, so it is guarded against being used as an SSRF proxy:

- Every request and redirect hop is checked; loopback, private, link-local (cloud metadata), reserved and multicast addresses are refused, including IPv4-mapped IPv6.
- Only `http`/`https`, no embedded credentials, max 5 redirects, 2 MB response cap, 45 s scan budget.
- Form payloads are only submitted to the scanned host, never to third parties.
- Per-IP rate limits (6 dynamic / 30 static scans per minute), 512 KB code limit, no internal error details in responses.
- Detected secrets are masked in evidence so reports can be shared.
- The site ships CSP, HSTS, `X-Frame-Options`, `Permissions-Policy` and `nosniff` headers (`vercel.json`).

Only scan systems you own or have written permission to test.

## Deployment (Vercel)

`vercel.json` builds the frontend to `frontend/dist` and serves the FastAPI app from `api/index.py` as a Python function under `/api/*`. Scan history is stored in the browser, since serverless instances do not share memory.

```bash
vercel --prod
```
