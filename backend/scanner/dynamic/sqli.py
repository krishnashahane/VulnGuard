import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

from ..models import Vulnerability, VulnType, Severity


ERROR_BASED_PAYLOADS = [
    "' OR '1'='1",
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "1; DROP TABLE test--",
    "' OR 1=1--",
    "1' ORDER BY 100--",
]

# Database error patterns that indicate SQL injection
SQL_ERROR_PATTERNS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "mysql_fetch",
    "mysql_num_rows",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "psql:",
    "unterminated quoted string",
    "syntax error at or near",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    "unrecognized token",
    # MSSQL
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "mssql_query",
    "odbc sql server driver",
    # Generic
    "sql syntax",
    "sql error",
    "database error",
    "query failed",
    "sqlstate",
]

TIME_BASED_PAYLOADS = [
    ("' OR SLEEP(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("' OR pg_sleep(5)--", 5),
]


class SQLiScanner:
    """Detects SQL injection via error-based and time-based blind techniques."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        baseline_params = {k: v[0] for k, v in params.items()}
        try:
            baseline = await self.client.get(
                urlunparse(parsed._replace(query=urlencode(baseline_params))), follow_redirects=True
            )
            baseline_body = baseline.text.lower()
        except httpx.RequestError:
            baseline_body = ""

        for param_name in params:
            # Error-based detection
            vuln = await self._test_error_based(parsed, params, param_name, baseline_body)
            if vuln:
                vulns.append(vuln)
                continue

            # Time-based blind detection
            vuln = await self._test_time_based(parsed, params, param_name)
            if vuln:
                vulns.append(vuln)

        return vulns

    async def _test_error_based(self, parsed, params: dict, param_name: str, baseline_body: str):
        for payload in ERROR_BASED_PAYLOADS:
            test_params = {**{k: v[0] for k, v in params.items()}, param_name: payload}
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            try:
                resp = await self.client.get(test_url, follow_redirects=True)
                body_lower = resp.text.lower()
                for pattern in SQL_ERROR_PATTERNS:
                    # Only count errors the payload caused, not ones already on the page
                    if pattern in body_lower and pattern not in baseline_body:
                        return Vulnerability(
                            type=VulnType.SQLI,
                            severity=Severity.CRITICAL,
                            title=f"SQL Injection in parameter '{param_name}'",
                            description=(
                                f"The parameter '{param_name}' is vulnerable to SQL injection. "
                                f"A database error was triggered by the test payload, indicating "
                                f"unsanitized input is passed directly to SQL queries."
                            ),
                            evidence=f"Payload: {payload} | Error pattern: '{pattern}' found in response",
                            location=f"Parameter: {param_name}",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 - Injection",
                        )
            except httpx.RequestError:
                continue
        return None

    async def _test_time_based(self, parsed, params: dict, param_name: str):
        # Get baseline response time
        baseline_params = {k: v[0] for k, v in params.items()}
        baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_params)))
        try:
            start = time.monotonic()
            await self.client.get(baseline_url, follow_redirects=True)
            baseline_time = time.monotonic() - start
        except httpx.RequestError:
            return None

        for payload, delay in TIME_BASED_PAYLOADS:
            test_params = {**baseline_params, param_name: payload}
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            try:
                start = time.monotonic()
                await self.client.get(test_url, follow_redirects=True, timeout=delay + 10)
                elapsed = time.monotonic() - start

                # Delay must be reproducible to rule out network jitter
                if elapsed >= baseline_time + delay - 1 and await self._confirm_delay(test_url, baseline_time, delay):
                    return Vulnerability(
                        type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        title=f"Blind SQL Injection (time-based) in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' appears vulnerable to blind SQL "
                            f"injection. A time-delay payload caused the server to respond "
                            f"~{elapsed:.1f}s vs baseline {baseline_time:.1f}s."
                        ),
                        evidence=f"Payload: {payload} | Response time: {elapsed:.1f}s (baseline: {baseline_time:.1f}s)",
                        location=f"Parameter: {param_name}",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection",
                    )
            except httpx.RequestError:
                continue
        return None

    async def _confirm_delay(self, test_url: str, baseline_time: float, delay: int) -> bool:
        try:
            start = time.monotonic()
            await self.client.get(test_url, follow_redirects=True, timeout=delay + 10)
            return time.monotonic() - start >= baseline_time + delay - 1
        except httpx.RequestError:
            return False
