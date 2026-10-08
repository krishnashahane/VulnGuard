import asyncio
import secrets
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from ..models import Vulnerability, VulnType, Severity


SENSITIVE_PATHS = [
    ("/.env", "Environment configuration file"),
    ("/.git/HEAD", "Git repository metadata"),
    ("/.DS_Store", "macOS directory metadata"),
    ("/wp-config.php", "WordPress configuration"),
    ("/phpinfo.php", "PHP info page"),
    ("/server-status", "Apache server status"),
    ("/server-info", "Apache server info"),
    ("/.htaccess", "Apache configuration"),
    ("/web.config", "IIS configuration"),
    ("/crossdomain.xml", "Flash cross-domain policy"),
    ("/backup.sql", "Database backup"),
    ("/dump.sql", "Database dump"),
    ("/database.sql", "Database export"),
    ("/admin", "Admin panel"),
    ("/console", "Debug console"),
]

# Content indicators that a path returned real data (not a generic 404 page)
CONTENT_INDICATORS = {
    "/.env": ["DB_", "APP_KEY", "SECRET", "PASSWORD", "API_KEY", "DATABASE_URL"],
    "/.git/HEAD": ["ref: refs/"],
    "/phpinfo.php": ["phpinfo()", "PHP Version", "php.ini"],
    "/server-status": ["Apache Server Status", "Server uptime"],
    "/wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
    "/backup.sql": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "/dump.sql": ["CREATE TABLE", "INSERT INTO"],
    "/database.sql": ["CREATE TABLE", "INSERT INTO"],
    "/.DS_Store": ["Bud1"],
    "/.htaccess": ["RewriteEngine", "Deny from", "Require all", "AuthType"],
    "/web.config": ["<configuration", "<system.webServer"],
    "/crossdomain.xml": ["<cross-domain-policy"],
}

HIGH_RISK_PATHS = {"/.env", "/.git/HEAD", "/backup.sql", "/dump.sql", "/database.sql", "/wp-config.php"}


class InfoDisclosureScanner:
    """Checks for exposed sensitive files, paths, and information leakage."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        parts = urlsplit(url)
        root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))

        # Many sites (SPAs, custom 404s) answer 200 for any path; learn what that looks like
        soft_404 = await self._get(urljoin(root, f"vulnguard-{secrets.token_hex(6)}"))
        soft_404_body = soft_404.text if soft_404 is not None and soft_404.status_code == 200 else None

        targets = [(path, desc, urljoin(root, path.lstrip("/"))) for path, desc in SENSITIVE_PATHS]
        responses = await asyncio.gather(*(self._get(t) for _, _, t in targets))

        vulns: list[Vulnerability] = []
        for (path, desc, target), resp in zip(targets, responses):
            if resp is None:
                continue
            if resp.status_code == 200 and self._is_real_content(path, resp.text, soft_404_body):
                vulns.append(Vulnerability(
                    type=VulnType.INFO_DISCLOSURE,
                    severity=Severity.HIGH if path in HIGH_RISK_PATHS else Severity.MEDIUM,
                    title=f"Sensitive File Exposed: {path}",
                    description=(
                        f"The file '{path}' ({desc}) is publicly accessible. "
                        f"This may expose sensitive configuration, credentials, "
                        f"or internal application details."
                    ),
                    evidence=f"HTTP {resp.status_code} at {target} (content length: {len(resp.text)})",
                    location=target,
                    cwe_id="CWE-538",
                    owasp_category="A05:2021 - Security Misconfiguration",
                ))
            elif resp.status_code in (401, 403) and path in ("/.env", "/.git/HEAD"):
                vulns.append(Vulnerability(
                    type=VulnType.INFO_DISCLOSURE,
                    severity=Severity.INFO,
                    title=f"Protected Resource Detected: {path}",
                    description=(
                        f"The path '{path}' returned HTTP {resp.status_code}. "
                        f"The resource may exist but is access-restricted. Ensure "
                        f"it's not accessible via alternative paths."
                    ),
                    evidence=f"HTTP {resp.status_code} at {target}",
                    location=target,
                    cwe_id="CWE-538",
                    owasp_category="A05:2021 - Security Misconfiguration",
                ))

        return vulns

    async def _get(self, target: str) -> httpx.Response | None:
        try:
            return await self.client.get(target, follow_redirects=False, timeout=10)
        except httpx.RequestError:
            return None

    def _is_real_content(self, path: str, body: str, soft_404_body: str | None) -> bool:
        """Verify the response contains expected content, not a catch-all page."""
        indicators = CONTENT_INDICATORS.get(path)
        if indicators:
            return any(ind.lower() in body.lower() for ind in indicators)
        if len(body) <= 50:
            return False
        if soft_404_body is not None:
            # Treat near-identical bodies as the site's generic fallback page
            size = max(len(body), len(soft_404_body), 1)
            return abs(len(body) - len(soft_404_body)) / size > 0.1 and body != soft_404_body
        return True
