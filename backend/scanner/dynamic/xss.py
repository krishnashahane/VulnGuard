from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

import httpx
from bs4 import BeautifulSoup

from ..models import Vulnerability, VulnType, Severity


XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    "'-alert(1)-'",
    '<body onload=alert(1)>',
]

CANARY = "VULNGUARD_XSS_"


class XSSScanner:
    """Detects reflected XSS by injecting test payloads into URL parameters and forms."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            resp = await self.client.get(url, follow_redirects=True)
        except httpx.RequestError:
            return vulns

        # Test URL parameter injection
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            vulns.extend(await self._test_params(parsed, params))

        # Test form inputs (resolved against the final URL after redirects)
        vulns.extend(await self._test_forms(str(resp.url), resp.text))

        return vulns

    async def _test_params(self, parsed, params: dict) -> list[Vulnerability]:
        vulns = []
        for param_name in params:
            for i, payload in enumerate(XSS_PAYLOADS):
                canary = f"{CANARY}{i}"
                test_payload = canary + payload
                test_params = {**{k: v[0] for k, v in params.items()}, param_name: test_payload}
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                try:
                    resp = await self.client.get(test_url, follow_redirects=True)
                    if canary in resp.text and payload in resp.text:
                        vulns.append(Vulnerability(
                            type=VulnType.XSS,
                            severity=Severity.HIGH,
                            title=f"Reflected XSS via parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' reflects user input without "
                                f"proper sanitization, allowing script injection."
                            ),
                            evidence=f"Payload: {payload} reflected in response body",
                            location=f"Parameter: {param_name}",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021 - Injection",
                        ))
                        break  # One finding per param is enough
                except httpx.RequestError:
                    continue
        return vulns

    async def _test_forms(self, url: str, html: str) -> list[Vulnerability]:
        vulns = []
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")[:10]
        origin_host = urlparse(url).hostname

        for form in forms:
            action = form.get("action") or ""
            form_url = urljoin(url, action)
            # Never submit payloads to third-party hosts referenced by the page
            if urlparse(form_url).hostname != origin_host or urlparse(form_url).scheme not in ("http", "https"):
                continue
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            text_inputs = [
                inp for inp in inputs
                if inp.get("type", "text") in ("text", "search", "email", "url", "hidden")
                and inp.get("name")
            ]

            if not text_inputs:
                continue

            for inp in text_inputs[:10]:
                name = inp["name"]
                payload = XSS_PAYLOADS[0]
                canary = f"{CANARY}form"
                data = {name: canary + payload}

                try:
                    if method == "post":
                        resp = await self.client.post(form_url, data=data, follow_redirects=True)
                    else:
                        resp = await self.client.get(form_url, params=data, follow_redirects=True)

                    if canary in resp.text and payload in resp.text:
                        vulns.append(Vulnerability(
                            type=VulnType.XSS,
                            severity=Severity.HIGH,
                            title=f"Reflected XSS via form input '{name}'",
                            description=(
                                f"Form input '{name}' in form action='{action}' reflects "
                                f"user input without sanitization."
                            ),
                            evidence=f"Payload reflected in response for input '{name}'",
                            location=f"Form action={action}, input={name}",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021 - Injection",
                        ))
                        break
                except httpx.RequestError:
                    continue
        return vulns
