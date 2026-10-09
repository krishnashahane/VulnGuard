from ..scanner.models import Vulnerability, VulnType, PatchSuggestion


PATCH_TEMPLATES: dict[VulnType, dict] = {
    VulnType.VULNERABLE_COMPONENT: {
        "title": "Upgrade Vulnerable Dependencies and Keep Them Patched",
        "description": (
            "Upgrade each flagged package to at least the version named in the finding, regenerate "
            "the lockfile, and re-run your tests. Automate this with Dependabot or Renovate and an "
            "audit step (pip-audit, npm audit) in CI so new advisories fail the build."
        ),
        "original_code": (
            '# requirements.txt\n'
            'django==2.2.0\n'
            'requests==2.31.0'
        ),
        "patched_code": (
            '# Upgrade each dependency to the fixed version reported by VulnGuard.\n'
            '# Example for requirements.txt:\n'
            'django==<fixed-version-from-finding>\n'
            'requests==<fixed-version-from-finding>\n\n'
            '# CI step\n'
            'pip install pip-audit && pip-audit -r requirements.txt'
        ),
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "https://osv.dev/",
        ],
    },
    VulnType.XSS: {
        "title": "Sanitize User Input / Use Context-Aware Output Encoding",
        "description": (
            "All user-supplied input must be sanitized before rendering in HTML. "
            "Use context-aware output encoding (HTML entity encoding for HTML context, "
            "JavaScript encoding for JS context, URL encoding for URL context)."
        ),
        "original_code": (
            '# Vulnerable: direct interpolation\n'
            'response = f"<div>Welcome, {user_input}</div>"'
        ),
        "patched_code": (
            'from markupsafe import escape\n\n'
            '# Safe: HTML-encode user input\n'
            'response = f"<div>Welcome, {escape(user_input)}</div>"'
        ),
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    VulnType.SQLI: {
        "title": "Use Parameterized Queries",
        "description": (
            "Never concatenate user input into SQL queries. Use parameterized "
            "queries (prepared statements) or an ORM to safely handle user input."
        ),
        "original_code": (
            '# Vulnerable: string concatenation in SQL\n'
            'query = f"SELECT * FROM users WHERE name = \'{username}\'"\n'
            'cursor.execute(query)'
        ),
        "patched_code": (
            '# Safe: parameterized query\n'
            'query = "SELECT * FROM users WHERE name = %s"\n'
            'cursor.execute(query, (username,))'
        ),
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
        ],
    },
    VulnType.CSRF: {
        "title": "Implement CSRF Token Protection",
        "description": (
            "Add CSRF tokens to all state-changing forms. Use a framework's built-in "
            "CSRF protection middleware and verify tokens on the server side."
        ),
        "original_code": (
            '<!-- Vulnerable: no CSRF token -->\n'
            '<form method="POST" action="/transfer">\n'
            '  <input name="amount" type="text">\n'
            '  <button type="submit">Transfer</button>\n'
            '</form>'
        ),
        "patched_code": (
            '<!-- Safe: CSRF token included -->\n'
            '<form method="POST" action="/transfer">\n'
            '  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">\n'
            '  <input name="amount" type="text">\n'
            '  <button type="submit">Transfer</button>\n'
            '</form>'
        ),
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    VulnType.SSRF: {
        "title": "Validate and Restrict Outbound URLs",
        "description": (
            "Validate all user-supplied URLs against an allowlist of permitted domains. "
            "Block requests to private/internal IP ranges and cloud metadata endpoints."
        ),
        "original_code": (
            '# Vulnerable: fetches any URL from user input\n'
            'import requests\n'
            'resp = requests.get(user_provided_url)'
        ),
        "patched_code": (
            'import ipaddress\n'
            'import socket\n'
            'from urllib.parse import urlparse\n'
            'import requests\n\n'
            'ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}\n\n'
            'def safe_fetch(url: str):\n'
            '    parsed = urlparse(url)\n'
            '    if parsed.hostname not in ALLOWED_HOSTS:\n'
            '        raise ValueError("Host not in allowlist")\n'
            '    # Also block private IPs\n'
            '    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n'
            '    if ip.is_private or ip.is_loopback:\n'
            '        raise ValueError("Private/loopback addresses blocked")\n'
            '    return requests.get(url, timeout=10)'
        ),
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    VulnType.CORS_MISCONFIG: {
        "title": "Restrict CORS to Trusted Origins",
        "description": (
            "Configure CORS to allow only specific, trusted origins. Never use "
            "wildcard (*) with credentials. Validate the Origin header against "
            "an explicit allowlist."
        ),
        "original_code": (
            '# Vulnerable: allows all origins\n'
            'app.add_middleware(\n'
            '    CORSMiddleware,\n'
            '    allow_origins=["*"],\n'
            '    allow_credentials=True,\n'
            ')'
        ),
        "patched_code": (
            '# Safe: explicit origin allowlist\n'
            'app.add_middleware(\n'
            '    CORSMiddleware,\n'
            '    allow_origins=["https://app.example.com"],\n'
            '    allow_credentials=True,\n'
            '    allow_methods=["GET", "POST"],\n'
            '    allow_headers=["Authorization", "Content-Type"],\n'
            ')'
        ),
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        ],
    },
    VulnType.SECURITY_HEADERS: {
        "title": "Add Security Headers",
        "description": (
            "Configure the web server or application to return security headers. "
            "At minimum, set CSP, HSTS, X-Frame-Options, and X-Content-Type-Options."
        ),
        "original_code": None,
        "patched_code": (
            '# FastAPI middleware example\n'
            'from starlette.middleware.base import BaseHTTPMiddleware\n\n'
            'class SecurityHeadersMiddleware(BaseHTTPMiddleware):\n'
            '    async def dispatch(self, request, call_next):\n'
            '        response = await call_next(request)\n'
            '        response.headers["X-Content-Type-Options"] = "nosniff"\n'
            '        response.headers["X-Frame-Options"] = "DENY"\n'
            '        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"\n'
            '        response.headers["Content-Security-Policy"] = "default-src \'self\'"\n'
            '        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"\n'
            '        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"\n'
            '        return response\n\n'
            'app.add_middleware(SecurityHeadersMiddleware)'
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
    },
    VulnType.INFO_DISCLOSURE: {
        "title": "Remove Sensitive Files and Suppress Version Info",
        "description": (
            "Remove or restrict access to sensitive files (.env, .git, backups). "
            "Configure the web server to suppress version information in headers."
        ),
        "original_code": None,
        "patched_code": (
            '# Nginx: suppress server version and block sensitive paths\n'
            'server_tokens off;\n\n'
            'location ~ /\\.(env|git|htaccess|DS_Store) {\n'
            '    deny all;\n'
            '    return 404;\n'
            '}\n\n'
            'location ~* \\.(sql|bak|backup|log)$ {\n'
            '    deny all;\n'
            '    return 404;\n'
            '}'
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
        ],
    },
    VulnType.HARDCODED_SECRET: {
        "title": "Use Environment Variables or a Secrets Manager",
        "description": (
            "Move all secrets (API keys, passwords, tokens) to environment variables "
            "or a secrets manager. Never hardcode secrets in source code."
        ),
        "original_code": (
            '# Vulnerable: hardcoded secret\n'
            'API_KEY = "sk-live-abc123def456"'
        ),
        "patched_code": (
            'import os\n\n'
            '# Safe: loaded from environment\n'
            'API_KEY = os.environ["API_KEY"]\n\n'
            '# Or with a default for development:\n'
            '# API_KEY = os.environ.get("API_KEY")\n'
            '# if not API_KEY:\n'
            '#     raise RuntimeError("API_KEY environment variable required")'
        ),
        "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
    },
    VulnType.INSECURE_AUTH: {
        "title": "Use Strong Password Hashing and Externalize Credentials",
        "description": (
            "Use bcrypt, scrypt, or Argon2id for password hashing. Never use MD5 or "
            "SHA1 for passwords. Externalize all credentials to environment variables."
        ),
        "original_code": (
            'import hashlib\n\n'
            '# Vulnerable: MD5 is broken for password hashing\n'
            'hashed = hashlib.md5(password.encode()).hexdigest()'
        ),
        "patched_code": (
            'import bcrypt\n\n'
            '# Safe: bcrypt with auto-generated salt\n'
            'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n\n'
            '# Verification:\n'
            'if bcrypt.checkpw(password.encode(), stored_hash):\n'
            '    print("Password matches")'
        ),
        "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        ],
    },
    VulnType.INSECURE_CONFIG: {
        "title": "Secure Application Configuration",
        "description": (
            "Disable debug mode in production. Use strong random SECRET_KEYs. "
            "Enable Secure and HttpOnly flags on cookies. Enforce HTTPS redirects."
        ),
        "original_code": (
            '# Vulnerable settings\n'
            'DEBUG = True\n'
            'SECRET_KEY = "changeme"\n'
            'ALLOWED_HOSTS = ["*"]'
        ),
        "patched_code": (
            'import os, secrets\n\n'
            '# Safe production settings\n'
            'DEBUG = False\n'
            'SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(64))\n'
            'ALLOWED_HOSTS = ["yourdomain.com", "www.yourdomain.com"]\n'
            'SESSION_COOKIE_SECURE = True\n'
            'SESSION_COOKIE_HTTPONLY = True\n'
            'CSRF_COOKIE_SECURE = True\n'
            'SECURE_SSL_REDIRECT = True'
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html",
        ],
    },
    VulnType.COMMAND_INJECTION: {
        "title": "Avoid Shell Commands / Use Safe Subprocess Calls",
        "description": (
            "Avoid os.system() and shell=True. Use subprocess with a list of "
            "arguments. Never pass user input to eval() or exec()."
        ),
        "original_code": (
            'import os\n\n'
            '# Vulnerable: user input in shell command\n'
            'os.system(f"ping {user_input}")'
        ),
        "patched_code": (
            'import subprocess\n'
            'import shlex\n\n'
            '# Safe: argument list, no shell\n'
            'result = subprocess.run(\n'
            '    ["ping", "-c", "4", validated_hostname],\n'
            '    capture_output=True,\n'
            '    text=True,\n'
            '    timeout=30\n'
            ')'
        ),
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
}


class PatchEngine:
    """Generates one remediation patch per vulnerability type, linked to every matching finding."""

    def generate_patches(self, vulnerabilities: list[Vulnerability]) -> list[PatchSuggestion]:
        by_type: dict[VulnType, PatchSuggestion] = {}

        for vuln in vulnerabilities:
            existing = by_type.get(vuln.type)
            if existing:
                existing.vulnerability_ids.append(vuln.id)
                continue

            template = PATCH_TEMPLATES.get(vuln.type)
            if not template:
                continue

            by_type[vuln.type] = PatchSuggestion(
                vulnerability_id=vuln.id,
                vulnerability_ids=[vuln.id],
                title=template["title"],
                description=template["description"],
                original_code=template.get("original_code"),
                patched_code=template.get("patched_code"),
                references=list(template.get("references", [])),
            )

        return list(by_type.values())
