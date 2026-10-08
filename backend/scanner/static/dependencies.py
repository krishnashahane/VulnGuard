"""Known-vulnerable dependency detection (OWASP A06) using the public OSV.dev database."""

import asyncio
import json
import re
from pathlib import PurePosixPath

import httpx

from ..models import Severity, Vulnerability, VulnType

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
MAX_PACKAGES = 500
MAX_DETAIL_LOOKUPS = 120
MAX_DETAILS_PER_PACKAGE = 12

SEVERITY_MAP = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}

REQUIREMENT_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][A-Za-z0-9.+!-]*)")
EXACT_SEMVER = re.compile(r"^[\^~=v]?\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")


def is_manifest(filename: str) -> bool:
    name = PurePosixPath(filename).name.lower()
    return name in ("package.json", "package-lock.json") or (name.startswith("requirements") and name.endswith(".txt"))


def parse_manifest(code: str, filename: str) -> list[tuple[str, str, str, int]]:
    """Return (ecosystem, name, version, line) for every pinned dependency we can resolve."""
    name = PurePosixPath(filename).name.lower()
    packages: list[tuple[str, str, str, int]] = []

    if name.endswith(".txt"):
        for line_num, line in enumerate(code.splitlines(), 1):
            match = REQUIREMENT_LINE.match(line.split("#", 1)[0])
            if match:
                packages.append(("PyPI", match.group(1).lower(), match.group(2), line_num))
        return packages

    try:
        data = json.loads(code)
    except (json.JSONDecodeError, RecursionError):
        return packages
    if not isinstance(data, dict):
        return packages

    if name == "package-lock.json" and isinstance(data.get("packages"), dict):
        for path, info in data["packages"].items():
            if path.startswith("node_modules/") and isinstance(info, dict) and isinstance(info.get("version"), str):
                packages.append(("npm", path.rsplit("node_modules/", 1)[-1], info["version"], 0))
        return packages

    lines = code.splitlines()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for pkg, spec in deps.items():
            match = EXACT_SEMVER.match(spec.strip()) if isinstance(spec, str) else None
            if match:
                line_num = next((i for i, l in enumerate(lines, 1) if f'"{pkg}"' in l), 0)
                packages.append(("npm", pkg, match.group(1), line_num))
    return packages


def _fixed_versions(vuln: dict, package: str) -> list[str]:
    fixed = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return fixed


def _severity(vuln: dict) -> Severity:
    label = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    return SEVERITY_MAP.get(label, Severity.MEDIUM)


class DependencyScanner:
    """Queries OSV for each pinned dependency in requirements*.txt, package.json and package-lock.json."""

    def __init__(self, client_factory=None):
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=15.0))

    async def scan(self, code: str, filename: str = "") -> list[Vulnerability]:
        return await self.scan_many([(filename, code)]) if is_manifest(filename) else []

    async def scan_many(self, files: list[tuple[str, str]]) -> list[Vulnerability]:
        packages = []
        seen = set()
        for filename, code in files:
            if not is_manifest(filename):
                continue
            for eco, name, version, line in parse_manifest(code, filename):
                if (eco, name, version) not in seen:
                    seen.add((eco, name, version))
                    packages.append((eco, name, version, line, filename))
        packages = packages[:MAX_PACKAGES]
        if not packages:
            return []

        async with self._client_factory() as client:
            resp = await client.post(OSV_BATCH_URL, json={"queries": [
                {"package": {"name": name, "ecosystem": eco}, "version": version}
                for eco, name, version, _, _ in packages
            ]})
            resp.raise_for_status()
            results = resp.json().get("results", [])

            hits = [(pkg, [v["id"] for v in res.get("vulns", [])]) for pkg, res in zip(packages, results) if res.get("vulns")]
            # Spread the lookup budget across packages so every hit gets severity and fix data
            ids = list(dict.fromkeys(i for _, vids in hits for i in vids[:MAX_DETAILS_PER_PACKAGE]))[:MAX_DETAIL_LOOKUPS]
            details = dict(zip(ids, await asyncio.gather(*(self._detail(client, i) for i in ids))))

        findings = []
        for (eco, name, version, line, filename), vuln_ids in hits:
            known = [details[i] for i in vuln_ids if details.get(i)]
            severity = max((_severity(v) for v in known), key=lambda s: Vulnerability.rank_of(s), default=Severity.MEDIUM)
            cves = sorted({a for v in known for a in v.get("aliases", []) if a.startswith("CVE-")})
            summaries = [v.get("summary") for v in known if v.get("summary")][:3]
            # Smallest fix above the current version per advisory; the highest of those clears them all
            per_advisory = [
                min((f for f in _fixed_versions(v, name) if _version_key(f) > _version_key(version)), key=_version_key, default=None)
                for v in known
            ]
            needed = [f for f in per_advisory if f]
            upgrade = max(needed, key=_version_key) if needed else None

            findings.append(Vulnerability(
                type=VulnType.VULNERABLE_COMPONENT,
                severity=severity,
                title=f"Vulnerable dependency: {name} {version}",
                description=(
                    f"{name} {version} ({eco}) has {len(vuln_ids)} published "
                    f"{'advisory' if len(vuln_ids) == 1 else 'advisories'}"
                    + (f": {'; '.join(summaries)}." if summaries else ".")
                    + (f" Upgrade to {upgrade} or later." if upgrade else " Check the advisories for a fixed release.")
                ),
                evidence=", ".join((cves or vuln_ids)[:8]) + (" ..." if len(cves or vuln_ids) > 8 else ""),
                location=f"{filename}:{line}" if line else filename,
                cwe_id="CWE-1395",
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
            ))
        return findings

    async def _detail(self, client: httpx.AsyncClient, vuln_id: str) -> dict | None:
        try:
            resp = await client.get(OSV_VULN_URL.format(vuln_id))
            return resp.json() if resp.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None


def _version_key(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.+-]", version)[:4])
