import httpx

from ..models import Vulnerability, VulnType, Severity


class CORSScanner:
    """Detects CORS misconfiguration by testing origin reflection and wildcard policies."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        test_origins = [
            "https://evil-attacker.com",
            "null",
            "https://sub.evil-attacker.com",
        ]

        for origin in test_origins:
            try:
                resp = await self.client.get(
                    url,
                    headers={"Origin": origin},
                    follow_redirects=True,
                )
            except httpx.RequestError:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            # Wildcard with credentials is dangerous
            if acao == "*" and acac == "true":
                vulns.append(Vulnerability(
                    type=VulnType.CORS_MISCONFIG,
                    severity=Severity.HIGH,
                    title="CORS Wildcard with Credentials",
                    description=(
                        "The server sets Access-Control-Allow-Origin: * alongside "
                        "Access-Control-Allow-Credentials: true. This allows any website "
                        "to make authenticated requests on behalf of users."
                    ),
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    location=url,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 - Broken Access Control",
                ))
                return vulns

            # Origin reflection (server echoes back arbitrary origin)
            if acao == origin and origin != "null":
                severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
                vulns.append(Vulnerability(
                    type=VulnType.CORS_MISCONFIG,
                    severity=severity,
                    title="CORS Origin Reflection",
                    description=(
                        f"The server reflects the Origin header value '{origin}' in "
                        f"Access-Control-Allow-Origin. This means any website can read "
                        f"responses from this origin."
                        + (" Combined with credentials, this allows full authenticated access."
                           if acac == "true" else "")
                    ),
                    evidence=f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
                    location=url,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 - Broken Access Control",
                ))
                return vulns

            # Null origin accepted (can be triggered from sandboxed iframes)
            if acao == "null" and origin == "null":
                vulns.append(Vulnerability(
                    type=VulnType.CORS_MISCONFIG,
                    severity=Severity.MEDIUM,
                    title="CORS Allows Null Origin",
                    description=(
                        "The server accepts 'null' as a valid origin. This can be exploited "
                        "via sandboxed iframes (sandbox attribute) to make cross-origin "
                        "requests."
                    ),
                    evidence=f"Origin: null -> ACAO: null",
                    location=url,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 - Broken Access Control",
                ))

        return vulns
