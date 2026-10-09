import re
from pathlib import PurePosixPath

from ..models import Vulnerability, VulnType, Severity


SECRET_PATTERNS = [
    # AWS
    (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS Access Key ID", Severity.CRITICAL),
    (r'(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key", Severity.CRITICAL),
    # Generic API keys
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key", Severity.HIGH),
    (r'(?:api[_-]?secret|apisecret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Secret", Severity.HIGH),
    # Passwords in assignments
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Hardcoded Password", Severity.CRITICAL),
    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    # Tokens
    (r'(?:token|auth_token|access_token|bearer)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Hardcoded Token", Severity.HIGH),
    # Connection strings
    (r'(?:mysql|postgresql|postgres|mongodb|redis)://[^\s"\']+', "Database Connection String", Severity.CRITICAL),
    # JWT secrets
    (r'(?:jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', "JWT Secret", Severity.CRITICAL),
    # Generic secrets
    (r'(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']([^"\']{8,})["\']', "Secret Key", Severity.HIGH),
    # GitHub/GitLab tokens
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Token", Severity.CRITICAL),
    (r'glpat-[A-Za-z0-9\-_]{20,}', "GitLab Token", Severity.CRITICAL),
]


# Values that merely restate the variable name ("secret-key", "password") are fixtures, not secrets.
GENERIC_VALUES = {"secret", "secretkey", "password", "passwd", "pwd", "key", "token", "apikey", "jwtsecret"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata"}


def is_test_path(filename: str) -> bool:
    path = PurePosixPath(filename.replace("\\", "/").lower())
    stem = path.stem
    return (
        any(part in TEST_DIRS for part in path.parts[:-1])
        or stem.startswith("test_")
        or stem.endswith(("_test", ".test", ".spec"))
    )


class SecretsScanner:
    """Detects hardcoded secrets, API keys, passwords, and tokens in source code."""

    async def scan(self, code: str, filename: str = "") -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        lines = code.split("\n")
        in_tests = is_test_path(filename)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pattern, secret_type, severity in SECRET_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Avoid false positives on example/placeholder values
                    matched_text = match.group(0)
                    value = match.group(1) if match.re.groups and match.group(1) else matched_text
                    if self._is_placeholder(matched_text) or re.sub(r"[\W_]", "", value.lower()) in GENERIC_VALUES:
                        continue

                    # Recognisable credential formats stay severe anywhere; generic assignments in tests are fixtures.
                    fixture = in_tests and bool(match.re.groups)
                    vulns.append(Vulnerability(
                        type=VulnType.HARDCODED_SECRET,
                        severity=Severity.LOW if fixture else severity,
                        title=f"{secret_type} Detected" + (" in Test Code" if fixture else ""),
                        description=(
                            f"A {secret_type.lower()} was found hardcoded in the source code. "
                            f"Secrets should be stored in environment variables or a secrets "
                            f"manager, never committed to source control."
                        ),
                        evidence=f"Pattern matched: {self._mask(match)}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id="CWE-798",
                        owasp_category="A02:2021 - Cryptographic Failures",
                    ))
                    break  # One finding per line

        return vulns

    def _is_placeholder(self, text: str) -> bool:
        placeholders = [
            "your_", "example", "xxx", "placeholder", "changeme",
            "todo", "fixme", "insert_", "replace_", "dummy",
            "test_key", "sample", "<your", "{your",
        ]
        text_lower = text.lower()
        return any(p in text_lower for p in placeholders)

    def _mask(self, match: re.Match) -> str:
        """Redact the secret itself so reports can be shared without re-leaking it."""
        text = match.group(0)
        secret = match.group(1) if match.re.groups and match.group(1) else text
        if len(secret) <= 8:
            redacted = "*" * len(secret)
        else:
            redacted = f"{secret[:4]}{'*' * min(len(secret) - 6, 24)}{secret[-2:]}"
        masked = text.replace(secret, redacted)
        return masked[:80] + ("..." if len(masked) > 80 else "")
