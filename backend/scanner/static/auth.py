import re

from ..models import Vulnerability, VulnType, Severity


WEAK_HASH_PATTERNS = [
    (r'hashlib\.md5\s*\(', "MD5", "CWE-328"),
    (r'hashlib\.sha1\s*\(', "SHA1", "CWE-328"),
    (r'md5\s*\(', "MD5 function", "CWE-328"),
    (r'sha1\s*\(', "SHA1 function", "CWE-328"),
]

HARDCODED_CRED_PATTERNS = [
    # Hardcoded passwords are reported by the secrets scanner (with placeholder filtering)
    (r'(?:username|user)\s*=\s*["\'](?:admin|root|test|user)["\']', "Hardcoded username"),
]

PERMISSIVE_CORS_PATTERNS = [
    (r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]', "FastAPI CORS wildcard"),
    (r'CORS_ALLOW_ALL_ORIGINS\s*=\s*True', "Django CORS allow all"),
    (r'Access-Control-Allow-Origin.*\*', "Manual CORS wildcard header"),
    (r"cors\s*\(\s*\)", "Express CORS with no config (allows all)"),
]


class AuthPatternScanner:
    """Detects insecure authentication patterns: weak hashing, hardcoded creds, permissive CORS."""

    async def scan(self, code: str, filename: str = "") -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Weak hashing for passwords
            for pattern, hash_name, cwe in WEAK_HASH_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if it seems password-related (look at surrounding context)
                    context = "\n".join(lines[max(0, line_num-3):line_num+2]).lower()
                    if any(w in context for w in ["password", "passwd", "pwd", "credential", "auth"]):
                        vulns.append(Vulnerability(
                            type=VulnType.INSECURE_AUTH,
                            severity=Severity.HIGH,
                            title=f"Weak Hash ({hash_name}) Used for Password",
                            description=(
                                f"{hash_name} is cryptographically broken and should not be "
                                f"used for password hashing. Use bcrypt, scrypt, or Argon2 "
                                f"with proper salt and iteration count."
                            ),
                            evidence=f"Code: {stripped[:100]}",
                            location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                            cwe_id=cwe,
                            owasp_category="A02:2021 - Cryptographic Failures",
                        ))
                        break

            # Hardcoded credentials
            for pattern, desc in HARDCODED_CRED_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type=VulnType.INSECURE_AUTH,
                        severity=Severity.HIGH,
                        title=f"Insecure Auth: {desc}",
                        description=(
                            f"Hardcoded credentials detected. Credentials should be stored in "
                            f"environment variables or a secrets manager and loaded at runtime."
                        ),
                        evidence=f"Code: {stripped[:80]}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id="CWE-798",
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                    ))
                    break

            # Permissive CORS
            for pattern, desc in PERMISSIVE_CORS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type=VulnType.CORS_MISCONFIG,
                        severity=Severity.MEDIUM,
                        title=f"Permissive CORS: {desc}",
                        description=(
                            f"Wildcard CORS origin detected in code. This allows any website "
                            f"to make requests to your API. Restrict origins to trusted domains."
                        ),
                        evidence=f"Code: {stripped[:100]}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id="CWE-942",
                        owasp_category="A01:2021 - Broken Access Control",
                    ))
                    break

        return vulns
