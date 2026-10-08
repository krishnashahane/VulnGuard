import re

from ..models import Vulnerability, VulnType, Severity


# Patterns that detect unsafe dynamic query/command construction
SQL_INJECTION_PATTERNS = [
    # f-string SQL
    (r'f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\{.*\}', "SQL query built with f-string"),
    # .format() SQL
    (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\.format\s*\(', "SQL query built with .format()"),
    # String concatenation SQL
    (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\+\s*(?:request|input|param|user|data|args)', "SQL query with string concatenation"),
    # % formatting SQL
    (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*%\s*\(', "SQL query built with % operator"),
]

COMMAND_INJECTION_PATTERNS = [
    (r'os\.system\s*\(', "os.system() call"),
    (r'os\.popen\s*\(', "os.popen() call"),
    (r'subprocess\.call\s*\(\s*[^[\]].*shell\s*=\s*True', "subprocess with shell=True"),
    (r'subprocess\.Popen\s*\(\s*[^[\]].*shell\s*=\s*True', "subprocess.Popen with shell=True"),
    (r'subprocess\.run\s*\(\s*[^[\]].*shell\s*=\s*True', "subprocess.run with shell=True"),
]

CODE_EXECUTION_PATTERNS = [
    (r'\beval\s*\(', "eval() usage"),
    (r'\bexec\s*\(', "exec() usage"),
    (r'__import__\s*\(', "Dynamic __import__() usage"),
    (r'compile\s*\(.*["\']exec["\']', "compile() with exec mode"),
]

DOM_INJECTION_PATTERNS = [
    (r'\.innerHTML\s*=', "Direct innerHTML assignment"),
    (r'\.outerHTML\s*=', "Direct outerHTML assignment"),
    (r'document\.write\s*\(', "document.write() usage"),
    (r'\.insertAdjacentHTML\s*\(', "insertAdjacentHTML() usage"),
]


class InjectionPatternScanner:
    """Detects injection-vulnerable patterns: SQL concatenation, command injection, eval/exec, DOM injection."""

    async def scan(self, code: str, filename: str = "") -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue

            # SQL injection patterns
            for pattern, desc in SQL_INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        title=f"Potential SQL Injection: {desc}",
                        description=(
                            f"Dynamic SQL query construction detected. User input may be "
                            f"interpolated directly into a SQL query, enabling SQL injection. "
                            f"Use parameterized queries or an ORM instead."
                        ),
                        evidence=f"Code: {stripped[:100]}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection",
                    ))
                    break

            # Command injection patterns
            for pattern, desc in COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type=VulnType.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        title=f"Potential Command Injection: {desc}",
                        description=(
                            f"System command execution detected. If user input reaches this "
                            f"call, an attacker could execute arbitrary commands on the server. "
                            f"Use subprocess with a list of arguments and shell=False."
                        ),
                        evidence=f"Code: {stripped[:100]}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 - Injection",
                    ))
                    break

            # Code execution patterns
            for pattern, desc in CODE_EXECUTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type=VulnType.COMMAND_INJECTION,
                        severity=Severity.HIGH,
                        title=f"Dangerous Code Execution: {desc}",
                        description=(
                            f"Dynamic code execution detected. eval() and exec() can execute "
                            f"arbitrary code and should be avoided. Use safer alternatives like "
                            f"ast.literal_eval() for parsing or explicit dispatch tables."
                        ),
                        evidence=f"Code: {stripped[:100]}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id="CWE-95",
                        owasp_category="A03:2021 - Injection",
                    ))
                    break

            # DOM injection patterns
            for pattern, desc in DOM_INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type=VulnType.XSS,
                        severity=Severity.HIGH,
                        title=f"DOM-Based XSS Risk: {desc}",
                        description=(
                            f"Direct DOM manipulation detected. {desc} can introduce XSS "
                            f"vulnerabilities if user-controlled data is inserted. Use "
                            f"textContent or a framework's safe rendering instead."
                        ),
                        evidence=f"Code: {stripped[:100]}",
                        location=f"{filename}:{line_num}" if filename else f"Line {line_num}",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 - Injection",
                    ))
                    break

        return vulns
