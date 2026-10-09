# VulnGuard

VulnGuard is a defensive web and source-code vulnerability scanner with a React/Vite frontend and a FastAPI backend.

It provides:

- **Dynamic scanning (DAST):** security headers, CORS, CSRF, information disclosure, XSS, SQL injection, and SSRF checks against public HTTP(S) targets.
- **Static scanning (SAST):** hardcoded secrets, unsafe SQL/command construction, dangerous code execution, insecure configuration, authentication issues, and dependency advisories.
- **Repository scanning:** scans public GitHub repositories in memory without checking them out to disk.
- **Patch suggestions:** generates remediation examples linked to detected vulnerability types.
- **Local scan history:** findings can be reviewed and exported from the browser.

> VulnGuard is a security testing aid, not a proof of security. Dynamic scanning should only be used against systems you own or are explicitly authorized to test.

## Requirements

- Python 3.11+
- Node.js 20.19+ for the current Vite toolchain
- npm
- Network access to GitHub/OSV.dev when repository/dependency scans are used

## Install

Install frontend dependencies:

```bash
npm install
```

Install backend dependencies:

```bash
python -m venv .venv

# macOS/Linux
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

## Run locally

Start the FastAPI backend:

```bash
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Start the React frontend in another terminal:

```bash
npm run dev
```

Open the Vite URL shown in the terminal, normally `http://localhost:5173`.

For a same-origin deployment, build the frontend and serve `dist/` behind your preferred web server/reverse proxy with the FastAPI application mounted at `/api`.

### Vercel

`vercel.json` builds the frontend into `dist/` and serves the FastAPI app from `api/index.py` as a Python function under `/api/*`, with CSP, HSTS and frame-blocking headers on the static site.

```bash
vercel --prod
```

On Vercel the edge overwrites `X-Real-IP`, so it is trusted for rate limiting automatically; set `VULNGUARD_TRUST_PROXY=false` to opt out.

## Environment

Copy the example configuration:

```bash
cp .env.example .env
```

Important backend settings:

```env
VULNGUARD_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
VULNGUARD_TRUST_PROXY=false
```

Set `VULNGUARD_TRUST_PROXY=true` only when a trusted reverse proxy is rewriting the forwarding headers correctly. Otherwise, client-controlled `X-Forwarded-For` / `X-Real-IP` values are ignored for rate limiting.

To use a different backend from the frontend:

```env
VITE_API_BASE=http://127.0.0.1:8000
```

## Scanning limits

The API intentionally applies bounded inputs:

- Static source: 512 KiB per submitted file.
- Multi-file scan: 50 files and 2 MiB total content.
- Repository archives: 20 MiB compressed, 150 MiB uncompressed, 600 scannable files, 4 MiB text content, and 256 KiB per file.
- Dynamic targets: URL length and outbound connection/body limits are bounded.
- Scan results are kept in a bounded in-memory store and are not durable across serverless instance restarts.

## Security controls

VulnGuard includes safeguards for running a scanner that makes outbound requests on user-supplied URLs:

- Only `http` and `https` targets are allowed.
- Embedded URL credentials are rejected.
- Private, loopback, link-local, reserved, and internal hostnames are blocked.
- DNS resolution is validated before outbound requests.
- Every outbound request is revalidated, including redirect hops.
- The scanner does not inherit ambient `HTTP_PROXY` / `HTTPS_PROXY` environment proxy settings.
- Response bodies are capped.
- API request sizes are bounded.
- API CORS is allowlist-based and does not enable credentialed wildcard access.
- JWTs, cookies, or authentication are not required by the scanner API itself.
- Security headers are added to API responses.
- Generated Python bytecode and local environment files are excluded from Git.

## Commands

```bash
npm run build       # production frontend build
npm run lint        # frontend lint
npm run preview     # preview the production frontend

npm run backend:dev     # FastAPI development server
npm run backend:test    # Python test suite
npm run backend:lint    # compile-check Python backend modules
```

## API

The backend exposes:

```text
GET  /api/health
POST /api/scan/dynamic
POST /api/scan/static
POST /api/scan/files
POST /api/scan/repo
GET  /api/scan/{scan_id}
```

Interactive OpenAPI documentation is available at:

```text
/api/docs
```

## Repository structure

```text
VulnGuard/
├── backend/
│   ├── api/                 # FastAPI routes
│   ├── patcher/             # remediation suggestions
│   └── scanner/
│       ├── dynamic/         # DAST checks + SSRF guard
│       └── static/          # SAST + dependency analysis
├── api/index.py             # Vercel serverless entry
├── src/                     # React frontend
├── public/                  # static frontend assets
├── tests/                   # backend tests
├── package.json
├── package-lock.json
├── vercel.json
├── requirements.txt
└── README.md
```

## Production notes

Run the backend behind a reverse proxy with TLS. Restrict `VULNGUARD_CORS_ORIGINS` to the exact frontend origins you operate.

Do not expose the dynamic scanning endpoint as an anonymous public scanning service without adding authentication, abuse controls, and a clear authorization policy.

## License

MIT
