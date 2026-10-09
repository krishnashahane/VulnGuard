import re

import httpx

from ..models import Severity, Vulnerability, VulnType

# Cookies whose theft means account takeover deserve a higher severity when unprotected.
SESSION_NAME = re.compile(r"sess|sid|auth|token|jwt|login|remember", re.IGNORECASE)


class CookieScanner:
    """Checks Set-Cookie flags on the landing page: Secure over HTTPS and HttpOnly on session cookies."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        try:
            resp = await self.client.get(url, follow_redirects=True)
        except httpx.RequestError:
            return []

        is_https = resp.url.scheme == "https"
        vulns: list[Vulnerability] = []
        for header in resp.headers.get_list("set-cookie"):
            name = header.split("=", 1)[0].strip()
            attrs = {a.strip().split("=", 1)[0].lower() for a in header.split(";")[1:]}
            session = bool(SESSION_NAME.search(name))
            if is_https and "secure" not in attrs:
                vulns.append(self._finding(
                    name, header, "Secure",
                    Severity.MEDIUM if session else Severity.LOW,
                    "the browser will also send it over plain HTTP, where it can be intercepted",
                    "CWE-614",
                ))
            if session and "httponly" not in attrs:
                vulns.append(self._finding(
                    name, header, "HttpOnly", Severity.MEDIUM,
                    "any injected script can read it and hijack the session",
                    "CWE-1004",
                ))
        return vulns

    @staticmethod
    def _finding(name: str, header: str, flag: str, severity: Severity, impact: str, cwe: str) -> Vulnerability:
        return Vulnerability(
            type=VulnType.INSECURE_COOKIE,
            severity=severity,
            title=f"Cookie '{name}' Missing {flag} Flag",
            description=f"The cookie '{name}' is set without the {flag} attribute, so {impact}.",
            evidence=f"Set-Cookie: {header[:120]}",
            location=f"Cookie: {name}",
            cwe_id=cwe,
            owasp_category="A05:2021 - Security Misconfiguration",
        )
