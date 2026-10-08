import httpx
from bs4 import BeautifulSoup

from ..models import Vulnerability, VulnType, Severity


CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "_csrf", "csrfmiddlewaretoken",
    "_token", "authenticity_token", "__requestverificationtoken",
    "antiforgery", "xsrf_token", "_xsrf",
]


class CSRFScanner:
    """Checks forms for CSRF protection tokens and cookie SameSite attributes."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            resp = await self.client.get(url, follow_redirects=True)
        except httpx.RequestError:
            return vulns

        # Check forms for CSRF tokens
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        post_forms = [f for f in forms if f.get("method", "").lower() == "post"]

        has_meta_token = any(
            any(t in (meta.get("name") or "").lower() for t in ("csrf", "xsrf"))
            for meta in soup.find_all("meta")
        )

        for form in post_forms:
            if not has_meta_token and not self._has_csrf_token(form):
                action = form.get("action", url)
                vulns.append(Vulnerability(
                    type=VulnType.CSRF,
                    severity=Severity.MEDIUM,
                    title="Missing CSRF Token in POST Form",
                    description=(
                        f"A POST form (action='{action}') does not contain a CSRF token. "
                        f"An attacker could craft a malicious page that submits this form "
                        f"on behalf of an authenticated user."
                    ),
                    evidence="No hidden input or meta tag matching known CSRF token names found",
                    location=f"Form action={action}",
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 - Broken Access Control",
                ))

        # Check cookies for SameSite attribute
        for cookie_header in resp.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()
            if "samesite" not in cookie_lower:
                vulns.append(Vulnerability(
                    type=VulnType.CSRF,
                    severity=Severity.LOW,
                    title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                    description=(
                        f"The cookie '{cookie_name}' does not set the SameSite attribute. "
                        f"Modern browsers default to Lax, but explicitly setting it is "
                        f"recommended for defense in depth."
                    ),
                    evidence=f"Set-Cookie header: {cookie_header[:100]}",
                    location=f"Cookie: {cookie_name}",
                    cwe_id="CWE-1275",
                    owasp_category="A01:2021 - Broken Access Control",
                ))

        return vulns

    def _has_csrf_token(self, form) -> bool:
        inputs = form.find_all("input", {"type": "hidden"})
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(token_name in name for token_name in CSRF_TOKEN_NAMES):
                return True
        return False
