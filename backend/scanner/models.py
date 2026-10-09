import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


# Share of risk one finding contributes; findings combine as independent events, so the score
# rises quickly with severe issues and never exceeds 100. One CRITICAL alone scores 50.
RISK_WEIGHTS = {
    Severity.CRITICAL: 0.5,
    Severity.HIGH: 0.3,
    Severity.MEDIUM: 0.06,
    Severity.LOW: 0.02,
    Severity.INFO: 0.0,
}


def risk_score(severities) -> int:
    safe = 1.0
    for s in severities:
        safe *= 1 - RISK_WEIGHTS[s]
    return round((1 - safe) * 100)


class VulnType(str, Enum):
    XSS = "XSS"
    SQLI = "SQLI"
    CSRF = "CSRF"
    SSRF = "SSRF"
    CORS_MISCONFIG = "CORS_MISCONFIG"
    SECURITY_HEADERS = "SECURITY_HEADERS"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    INSECURE_AUTH = "INSECURE_AUTH"
    INSECURE_CONFIG = "INSECURE_CONFIG"
    VULNERABLE_COMPONENT = "VULNERABLE_COMPONENT"
    LOGGING_FAILURE = "LOGGING_FAILURE"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    INSECURE_COOKIE = "INSECURE_COOKIE"


class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: VulnType
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    location: str = ""
    cwe_id: Optional[str] = None
    owasp_category: str = ""

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    @staticmethod
    def rank_of(severity: "Severity") -> int:
        return SEVERITY_ORDER[severity]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PatchSuggestion(BaseModel):
    vulnerability_id: str
    vulnerability_ids: list[str] = []
    title: str
    description: str
    original_code: Optional[str] = None
    patched_code: Optional[str] = None
    references: list[str] = []


class CheckResult(BaseModel):
    name: str
    status: str  # passed | failed | not_tested | skipped | error
    findings: int = 0
    detail: str = ""


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    scan_type: str  # "dynamic" or "static"
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
    vulnerabilities: list[Vulnerability] = []
    patches: list[PatchSuggestion] = []
    summary: dict = {}
    warnings: list[str] = []
    stats: dict = {}
    checks: list[CheckResult] = []
    risk_score: int = 0

    def compute_summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        self.summary = {"total": len(self.vulnerabilities), **counts}
        self.risk_score = risk_score(v.severity for v in self.vulnerabilities)
        return self.summary


MAX_CODE_BYTES = 512 * 1024
MAX_FILES = 50
MAX_TOTAL_BYTES = 2 * 1024 * 1024


class SourceFile(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(max_length=MAX_CODE_BYTES)


class FilesScanRequest(BaseModel):
    files: list[SourceFile] = Field(min_length=1, max_length=MAX_FILES)


class RepoScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=300)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=MAX_CODE_BYTES)
    scan_type: str = "dynamic"
    filename: Optional[str] = Field(default=None, max_length=255)
