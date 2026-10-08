from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

from ..models import Vulnerability, VulnType, Severity


# Internal/private IP ranges used to test for SSRF
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
]

# Parameter names that commonly accept URLs
URL_PARAM_NAMES = [
    "url", "uri", "path", "next", "redirect", "return",
    "callback", "go", "link", "target", "dest", "destination",
    "rurl", "return_url", "redirect_url", "feed", "host", "site",
    "src", "source", "ref", "page", "file", "load",
]

# Patterns that suggest internal resource access
INTERNAL_INDICATORS = [
    "root:", "/etc/passwd", "ami-id", "instance-id",
    "internal server", "connection refused", "couldn't connect",
    "ssh-", "mysql", "postgresql",
]


class SSRFScanner:
    """Detects Server-Side Request Forgery by testing URL parameters with internal addresses."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        target_params = [name for name in params if name.lower() in URL_PARAM_NAMES] or list(params)
        base_params = {k: v[0] for k, v in params.items()}

        for param_name in target_params:
            baseline_body = await self._fetch(parsed, {**base_params, param_name: "https://example.com/"})
            if baseline_body is None:
                continue

            for payload in SSRF_PAYLOADS:
                body = await self._fetch(parsed, {**base_params, param_name: payload})
                if body is None:
                    continue
                # Indicator must be introduced by the internal payload, not present on every response
                for indicator in INTERNAL_INDICATORS:
                    if indicator in body and indicator not in baseline_body:
                        return [Vulnerability(
                            type=VulnType.SSRF,
                            severity=Severity.CRITICAL,
                            title=f"Potential SSRF via parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' may be vulnerable to SSRF. "
                                f"Supplying an internal address produced content that did not "
                                f"appear when a public URL was supplied."
                            ),
                            evidence=f"Payload: {payload} | Indicator: '{indicator}' found in response",
                            location=f"Parameter: {param_name}",
                            cwe_id="CWE-918",
                            owasp_category="A10:2021 - Server-Side Request Forgery",
                        )]
        return []

    async def _fetch(self, parsed, query: dict) -> str | None:
        test_url = urlunparse(parsed._replace(query=urlencode(query)))
        try:
            resp = await self.client.get(test_url, follow_redirects=False, timeout=10)
        except httpx.RequestError:
            return None
        return resp.text.lower()
