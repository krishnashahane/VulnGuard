import asyncio

import httpx

from ..models import Vulnerability
from .netguard import GuardedTransport
from .xss import XSSScanner
from .sqli import SQLiScanner
from .csrf import CSRFScanner
from .headers import HeadersScanner
from .ssrf import SSRFScanner
from .cors import CORSScanner
from .info_disclosure import InfoDisclosureScanner

SCANNERS = [
    ("Security headers", HeadersScanner),
    ("CORS", CORSScanner),
    ("CSRF", CSRFScanner),
    ("Information disclosure", InfoDisclosureScanner),
    ("XSS", XSSScanner),
    ("SQL injection", SQLiScanner),
    ("SSRF", SSRFScanner),
]


class DynamicScanner:
    """Runs all dynamic checks concurrently against a target URL within a time budget."""

    def __init__(self, budget_seconds: float = 45.0, allow_private: bool = False):
        self.budget = budget_seconds
        self.allow_private = allow_private
        self.warnings: list[str] = []

    async def scan(self, url: str) -> list[Vulnerability]:
        self.warnings = []
        all_vulns: list[Vulnerability] = []

        async with httpx.AsyncClient(
            transport=GuardedTransport(allow_private=self.allow_private),
            timeout=httpx.Timeout(10.0, connect=5.0),
            limits=httpx.Limits(max_connections=12),
            max_redirects=5,
            headers={"User-Agent": "VulnGuard/1.1 Security Scanner", "Accept-Encoding": "identity"},
        ) as client:
            tasks = {
                asyncio.create_task(cls(client).scan(url)): name for name, cls in SCANNERS
            }
            done, pending = await asyncio.wait(tasks, timeout=self.budget)

            for task in pending:
                task.cancel()
                self.warnings.append(f"{tasks[task]} check timed out and was skipped")
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

            for task in done:
                if task.exception() is not None:
                    self.warnings.append(f"{tasks[task]} check failed to complete")
                    continue
                all_vulns.extend(task.result())

        return sorted(all_vulns, key=lambda v: (-v.severity_rank, v.title))
