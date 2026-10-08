import httpx

from ..models import Vulnerability, VulnType, Severity


REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": (
            "Content-Security-Policy header is missing. CSP helps prevent XSS attacks "
            "by specifying which content sources are allowed to load."
        ),
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": (
            "X-Frame-Options header is missing. This allows the page to be loaded in "
            "iframes, making it vulnerable to clickjacking attacks."
        ),
        "cwe": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": (
            "X-Content-Type-Options header is missing. Without 'nosniff', browsers may "
            "MIME-sniff responses, potentially executing uploaded content as scripts."
        ),
        "cwe": "CWE-16",
    },
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": (
            "Strict-Transport-Security (HSTS) header is missing. The site does not "
            "enforce HTTPS connections, leaving users vulnerable to downgrade attacks."
        ),
        "cwe": "CWE-319",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": (
            "Referrer-Policy header is missing. Without it, the browser may send the "
            "full URL in the Referer header, potentially leaking sensitive information."
        ),
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": (
            "Permissions-Policy header is missing. This header controls which browser "
            "features (camera, microphone, geolocation) can be used by the page."
        ),
        "cwe": "CWE-16",
    },
}


class HeadersScanner:
    """Checks for the presence and configuration of security-related HTTP headers."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            resp = await self.client.get(url, follow_redirects=True)
        except httpx.RequestError:
            return vulns

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        csp = headers_lower.get("content-security-policy", "").lower()
        is_https = resp.url.scheme == "https"

        for header_name, info in REQUIRED_HEADERS.items():
            # HSTS is only honoured over HTTPS; CSP frame-ancestors supersedes X-Frame-Options
            if header_name == "Strict-Transport-Security" and not is_https:
                continue
            if header_name == "X-Frame-Options" and "frame-ancestors" in csp:
                continue
            if header_name.lower() not in headers_lower:
                vulns.append(Vulnerability(
                    type=VulnType.SECURITY_HEADERS,
                    severity=info["severity"],
                    title=f"Missing Security Header: {header_name}",
                    description=info["description"],
                    evidence=f"Header '{header_name}' not found in response",
                    location=url,
                    cwe_id=info["cwe"],
                    owasp_category="A05:2021 - Security Misconfiguration",
                ))

        if not is_https:
            vulns.append(Vulnerability(
                type=VulnType.SECURITY_HEADERS,
                severity=Severity.MEDIUM,
                title="Site Served Over Plain HTTP",
                description=(
                    "The final response was delivered over unencrypted HTTP. Traffic can be read "
                    "or modified in transit. Redirect all HTTP traffic to HTTPS and enable HSTS."
                ),
                evidence=f"Final URL: {resp.url}",
                location=str(resp.url),
                cwe_id="CWE-319",
                owasp_category="A02:2021 - Cryptographic Failures",
            ))

        # Check for deprecated X-XSS-Protection with unsafe value
        xss_prot = headers_lower.get("x-xss-protection", "")
        if xss_prot and "1; mode=block" not in xss_prot and xss_prot != "0":
            vulns.append(Vulnerability(
                type=VulnType.SECURITY_HEADERS,
                severity=Severity.INFO,
                title="X-XSS-Protection Header Misconfigured",
                description=(
                    "X-XSS-Protection is set but not to '0' or '1; mode=block'. "
                    "Note: This header is largely deprecated in favor of CSP."
                ),
                evidence=f"X-XSS-Protection: {xss_prot}",
                location=url,
                cwe_id="CWE-16",
                owasp_category="A05:2021 - Security Misconfiguration",
            ))

        # Check for server version disclosure
        server = headers_lower.get("server", "")
        if server and any(c.isdigit() for c in server):
            vulns.append(Vulnerability(
                type=VulnType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                title="Server Version Disclosed in Header",
                description=(
                    f"The Server header discloses version information: '{server}'. "
                    f"This helps attackers identify known vulnerabilities for the server."
                ),
                evidence=f"Server: {server}",
                location=url,
                cwe_id="CWE-200",
                owasp_category="A05:2021 - Security Misconfiguration",
            ))

        return vulns
