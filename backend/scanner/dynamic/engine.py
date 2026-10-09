import asyncio
from urllib.parse import parse_qs, urldefrag, urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from ..models import CheckResult, Vulnerability
from .netguard import GuardedTransport
from .xss import XSSScanner
from .sqli import SQLiScanner
from .csrf import CSRFScanner
from .headers import HeadersScanner
from .ssrf import SSRFScanner
from .cors import CORSScanner
from .cookies import CookieScanner
from .info_disclosure import InfoDisclosureScanner

# Checks that look at the landing page itself.
PAGE_CHECKS = [
    ("Security headers", HeadersScanner),
    ("Cookies", CookieScanner),
    ("CORS", CORSScanner),
    ("CSRF", CSRFScanner),
    ("Information disclosure", InfoDisclosureScanner),
]
# Checks that need query parameters to inject into.
INPUT_CHECKS = [
    ("XSS", XSSScanner),
    ("SQL injection", SQLiScanner),
    ("SSRF", SSRFScanner),
]
CHECK_NAMES = [name for name, _ in PAGE_CHECKS + INPUT_CHECKS]

MAX_DISCOVERED = 3


class TargetUnreachable(Exception):
    """The target could not be fetched at all, so no check can produce a meaningful result."""


def discover_inputs(base_url: str, html: str) -> list[str]:
    """Same-host links with query parameters, one per distinct path + parameter set."""
    host = urlsplit(base_url).hostname
    seen: set[tuple[str, tuple[str, ...]]] = set()
    found: list[str] = []
    for a in BeautifulSoup(html, "html.parser").find_all("a", href=True, limit=500):
        url = urldefrag(urljoin(base_url, a["href"].strip()))[0]
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or parts.hostname != host or not parts.query:
            continue
        key = (parts.path, tuple(sorted(parse_qs(parts.query))))
        if not key[1] or key in seen:
            continue
        seen.add(key)
        found.append(url)
        if len(found) >= MAX_DISCOVERED:
            break
    return found


class DynamicScanner:
    """Runs all dynamic checks concurrently against a target URL within a time budget."""

    def __init__(self, budget_seconds: float = 45.0, allow_private: bool = False):
        self.budget = budget_seconds
        self.allow_private = allow_private
        self.warnings: list[str] = []
        self.checks: list[CheckResult] = []
        self.discovered: list[str] = []

    async def scan(self, url: str) -> list[Vulnerability]:
        self.warnings, self.checks, self.discovered = [], [], []

        async with httpx.AsyncClient(
            transport=GuardedTransport(allow_private=self.allow_private),
            timeout=httpx.Timeout(10.0, connect=5.0),
            limits=httpx.Limits(max_connections=12),
            max_redirects=5,
            headers={"User-Agent": "VulnGuard/1.2 Security Scanner", "Accept-Encoding": "identity"},
        ) as client:
            try:
                landing = await client.get(url, follow_redirects=True)
            except httpx.TimeoutException as exc:
                raise TargetUnreachable("The site did not respond in time.") from exc
            except httpx.TooManyRedirects as exc:
                raise TargetUnreachable("The site redirects in a loop.") from exc
            except httpx.RequestError as exc:
                if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "SSL" in str(exc):
                    raise TargetUnreachable("The site's TLS certificate is invalid or untrusted.") from exc
                raise TargetUnreachable("Could not connect to the site.") from exc

            has_params = bool(urlsplit(url).query)
            has_forms = "<form" in landing.text.lower()
            self.discovered = [u for u in discover_inputs(str(landing.url), landing.text) if u != url]
            input_urls = ([url] if has_params else []) + self.discovered

            # Each task is (check name, discovered URL or None, coroutine).
            jobs: list[tuple[str, str | None, object]] = [(name, None, cls(client).scan(url)) for name, cls in PAGE_CHECKS]
            jobs.append(("XSS", None, XSSScanner(client).scan(url)))
            jobs += [("XSS", u, XSSScanner(client).scan_params(u)) for u in self.discovered]
            for name, cls in INPUT_CHECKS[1:]:
                jobs += [(name, u if u != url else None, cls(client).scan(u)) for u in input_urls]

            tasks = {asyncio.create_task(coro): (name, src) for name, src, coro in jobs}
            done, pending = await asyncio.wait(tasks, timeout=self.budget)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        found: dict[str, list[Vulnerability]] = {name: [] for name in CHECK_NAMES}
        errored, timed_out = set(), set()
        for task, (name, src) in tasks.items():
            if task in pending:
                timed_out.add(name)
            elif task.exception() is not None:
                errored.add(name)
            else:
                for v in task.result():
                    if src:
                        path = urlsplit(src).path or "/"
                        v.title = f"{v.title} on {path}"
                        v.location = f"{path} · {v.location}"
                    found[name].append(v)

        for name in CHECK_NAMES:
            n = len(found[name])
            applicable = name not in dict(INPUT_CHECKS) or input_urls or (name == "XSS" and has_forms)
            if n:
                status, detail = "failed", f"{n} issue{'s' if n > 1 else ''} found"
            elif name in timed_out:
                status, detail = "skipped", "Timed out before finishing"
                self.warnings.append(f"{name} check timed out and was skipped")
            elif name in errored:
                status, detail = "error", "Could not complete"
                self.warnings.append(f"{name} check failed to complete")
            elif not applicable:
                status, detail = "not_tested", "No query parameters or forms found to test"
            else:
                status, detail = "passed", "No issues found"
            self.checks.append(CheckResult(name=name, status=status, findings=n, detail=detail))

        vulns = [v for name in CHECK_NAMES for v in found[name]]
        return sorted(vulns, key=lambda v: (-v.severity_rank, v.title))
