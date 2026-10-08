import re

from ..models import Vulnerability, VulnType, Severity


CONFIG_PATTERNS = [
    # Flask debug
    {
        "pattern": r'app\.run\s*\(.*debug\s*=\s*True',
        "title": "Flask Debug Mode Enabled",
        "description": (
            "Flask application runs with debug=True. This enables the interactive "
            "debugger, which allows arbitrary code execution from the browser."
        ),
        "severity": Severity.CRITICAL,
        "cwe": "CWE-489",
    },
    # Debug mode
    {
        "pattern": r'DEBUG\s*=\s*True',
        "title": "Debug Mode Enabled",
        "description": (
            "Debug mode is enabled. This can expose detailed error pages, stack traces, "
            "and internal application state to users. Disable in production."
        ),
        "severity": Severity.HIGH,
        "cwe": "CWE-489",
    },
    # Weak secret key
    {
        "pattern": r'SECRET_KEY\s*=\s*["\'](?:secret|changeme|default|key|test|password|django-insecure)["\']',
        "title": "Weak/Default SECRET_KEY",
        "description": (
            "The SECRET_KEY is set to a weak or default value. This compromises session "
            "security, CSRF protection, and any cryptographic signing. Generate a strong "
            "random key of at least 50 characters."
        ),
        "severity": Severity.CRITICAL,
        "cwe": "CWE-1188",
    },
    # Wildcard allowed hosts
    {
        "pattern": r'ALLOWED_HOSTS\s*=\s*\[\s*["\'\s]*\*["\'\s]*\]',
        "title": "ALLOWED_HOSTS Accepts All Hosts",
        "description": (
            "ALLOWED_HOSTS is set to ['*'], accepting requests for any hostname. "
            "This can enable host header injection attacks. Set to specific domains."
        ),
        "severity": Severity.MEDIUM,
        "cwe": "CWE-16",
    },
    # Insecure cookie settings
    {
        "pattern": r'(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False',
        "title": "Cookie Secure Flag Disabled",
        "description": (
            "Secure flag is disabled for cookies. Cookies will be sent over unencrypted "
            "HTTP connections, exposing session tokens to interception."
        ),
        "severity": Severity.MEDIUM,
        "cwe": "CWE-614",
    },
    {
        "pattern": r'(?:SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_HTTPONLY)\s*=\s*False',
        "title": "Cookie HttpOnly Flag Disabled",
        "description": (
            "HttpOnly flag is disabled for cookies. JavaScript can access cookie values, "
            "making session tokens vulnerable to XSS theft."
        ),
        "severity": Severity.MEDIUM,
        "cwe": "CWE-1004",
    },
    # HTTPS redirect disabled
    {
        "pattern": r'SECURE_SSL_REDIRECT\s*=\s*False',
        "title": "HTTPS Redirect Disabled",
        "description": (
            "HTTPS redirect is explicitly disabled. Users accessing the site via HTTP "
            "will not be redirected, leaving traffic unencrypted."
        ),
        "severity": Severity.MEDIUM,
        "cwe": "CWE-319",
    },
    # Sensitive logging
    {
        "pattern": r'(?:log|logger|logging)\.\w+\(.*(?:password|secret|token|key|credential)',
        "title": "Sensitive Data in Log Statement",
        "description": (
            "Sensitive data (password, secret, token) appears to be logged. "
            "Log files are often stored in plaintext and shared widely. "
            "Remove or mask sensitive values before logging."
        ),
        "severity": Severity.MEDIUM,
        "cwe": "CWE-532",
    },
]


class ConfigScanner:
    """Detects insecure configuration: debug mode, weak keys, insecure cookies, etc."""

    async def scan(self, code: str, filename: str = "") -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for cfg in CONFIG_PATTERNS:
                if re.search(cfg["pattern"], line, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type=VulnType.INSECURE_CONFIG,
                        severity=cfg["severity"],
                        title=cfg["title"],
                        description=cfg["description"],
                        evidence=f"Code: {stripped[:100]}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id=cfg["cwe"],
                        owasp_category="A05:2021 - Security Misconfiguration",
                    ))
                    break

        return vulns
