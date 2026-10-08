from pathlib import PurePosixPath

from ..models import Vulnerability
from .secrets import SecretsScanner
from .injection import InjectionPatternScanner
from .auth import AuthPatternScanner
from .config import ConfigScanner
from .dependencies import DependencyScanner

# Minified bundles can have megabyte-long lines; cap them so regexes stay linear in practice
MAX_LINE_LENGTH = 2000
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock"}


class StaticScanner:
    """Runs pattern-based SAST rules and dependency advisories over one or many source files."""

    def __init__(self, dependency_scanner: DependencyScanner | None = None):
        self.pattern_scanners = [
            SecretsScanner(),
            InjectionPatternScanner(),
            AuthPatternScanner(),
            ConfigScanner(),
        ]
        self.dependency_scanner = dependency_scanner or DependencyScanner()
        self.warnings: list[str] = []

    async def scan(self, code: str, filename: str = "") -> list[Vulnerability]:
        return await self.scan_files([(filename, code)])

    async def scan_files(self, files: list[tuple[str, str]]) -> list[Vulnerability]:
        self.warnings = []
        all_vulns: list[Vulnerability] = []
        seen: set[tuple[str, str]] = set()

        def add(vulns):
            for vuln in vulns:
                key = (vuln.location, vuln.cwe_id or vuln.title)
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(vuln)

        for filename, code in files:
            if PurePosixPath(filename).name.lower() in LOCKFILES:
                continue
            code = "\n".join(line[:MAX_LINE_LENGTH] for line in code.splitlines())
            for scanner in self.pattern_scanners:
                try:
                    add(await scanner.scan(code, filename))
                except Exception:
                    continue

        try:
            add(await self.dependency_scanner.scan_many(files))
        except Exception:
            self.warnings.append("Dependency advisory lookup (OSV.dev) was unavailable; dependencies were not checked")

        return sorted(all_vulns, key=lambda v: -v.severity_rank)
