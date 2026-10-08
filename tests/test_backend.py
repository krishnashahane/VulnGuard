import asyncio

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.testclient import TestClient

from backend.main import app
from backend.patcher.engine import PatchEngine
from backend.scanner.dynamic.engine import DynamicScanner
from backend.scanner.dynamic.netguard import GuardedTransport, UnsafeTargetError, validate_target_url
from backend.scanner.models import VulnType
from backend.scanner.static.engine import StaticScanner

client = TestClient(app)

VULNERABLE_CODE = '''
import os, hashlib
DEBUG = True
SECRET_KEY = "secret"
password = "hunter2hunter2"
AWS = "AKIAABCDEFGHIJKLMNOP"
query = f"SELECT * FROM users WHERE id = '{user_id}'"
os.system(f"ping {host}")
pw_hash = hashlib.md5(password.encode())
el.innerHTML = userInput
# password = "commented_out_value"
api_key = "your_api_key_here_placeholder"
'''


def run(coro):
    return asyncio.run(coro)


# --- netguard -------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1",
    "http://localhost:8000",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://10.0.0.5",
    "http://192.168.1.1",
    "http://0.0.0.0",
    "http://[::ffff:127.0.0.1]/",
    "file:///etc/passwd",
    "gopher://example.com",
    "http://user:pass@example.com",
    "http://foo.internal",
    "",
])
def test_unsafe_targets_rejected(url):
    with pytest.raises(UnsafeTargetError):
        run(validate_target_url(url))


def test_public_literal_ip_allowed():
    assert run(validate_target_url("1.1.1.1")) == "https://1.1.1.1"


def test_transport_blocks_redirect_to_private_address():
    async def go():
        async with httpx.AsyncClient(transport=GuardedTransport()) as c:
            await c.get("http://127.0.0.1:1/")
    with pytest.raises(httpx.ConnectError, match="private"):
        run(go())


# --- static analysis ------------------------------------------------------

def test_static_scanner_finds_expected_issues():
    vulns = run(StaticScanner().scan(VULNERABLE_CODE, "app.py"))
    titles = " | ".join(v.title for v in vulns)
    for expected in ["Debug Mode", "SECRET_KEY", "Hardcoded Password", "AWS Access Key",
                     "SQL Injection", "Command Injection", "MD5", "innerHTML"]:
        assert expected in titles, expected
    locations = {v.location for v in vulns}
    assert "app.py:11" not in locations  # commented line ignored
    assert "app.py:12" not in locations  # placeholder ignored
    # sorted most severe first
    ranks = [v.severity_rank for v in vulns]
    assert ranks == sorted(ranks, reverse=True)


def test_static_scanner_no_duplicate_password_finding():
    vulns = run(StaticScanner().scan('password = "hunter2hunter2"', "x.py"))
    assert len(vulns) == 1


def test_static_scanner_survives_huge_line():
    vulns = run(StaticScanner().scan("SELECT " + "a{" * 200_000, "min.js"))
    assert isinstance(vulns, list)


def test_patches_link_every_vulnerability_of_a_type():
    vulns = run(StaticScanner().scan('DEBUG = True\nSECURE_SSL_REDIRECT = False\n', "s.py"))
    patches = PatchEngine().generate_patches(vulns)
    assert len(patches) == 1
    assert set(patches[0].vulnerability_ids) == {v.id for v in vulns}


# --- API ------------------------------------------------------------------

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_static_endpoint_and_lookup():
    r = client.post("/api/scan/static", json={"target": VULNERABLE_CODE, "filename": "app.py"})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["total"] == len(body["vulnerabilities"]) > 0
    assert body["completed_at"].endswith(("Z", "+00:00"))
    assert client.get(f"/api/scan/{body['id']}").status_code == 200
    assert client.get("/api/scan/does-not-exist").status_code == 404


def test_static_endpoint_rejects_empty_and_oversize():
    assert client.post("/api/scan/static", json={"target": ""}).status_code == 422
    assert client.post("/api/scan/static", json={"target": "a" * (512 * 1024 + 1)}).status_code == 422


def test_dynamic_endpoint_blocks_internal_targets():
    for target in ["http://127.0.0.1:8000", "169.254.169.254", "localhost"]:
        r = client.post("/api/scan/dynamic", json={"target": target}, headers={"x-real-ip": "203.0.113.9"})
        assert r.status_code == 400, target


def test_dynamic_endpoint_rate_limited():
    codes = [
        client.post("/api/scan/dynamic", json={"target": "http://127.0.0.1"}, headers={"x-real-ip": "203.0.113.77"}).status_code
        for _ in range(8)
    ]
    assert 429 in codes


def test_cors_not_wildcard():
    r = client.options("/api/scan/static", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") != "*"
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"


# --- dynamic scanning against an in-process vulnerable app ----------------

vuln_app = FastAPI()


@vuln_app.get("/", response_class=HTMLResponse)
async def home(q: str = ""):
    return f'<html><body>Hello {q}<form method="post" action="/login"><input name="user"></form></body></html>'


@vuln_app.get("/item", response_class=HTMLResponse)
async def item(id: str = "1"):
    if "'" in id:
        return HTMLResponse("You have an error in your SQL syntax", status_code=500)
    return "item ok"


@vuln_app.get("/.env", response_class=PlainTextResponse)
async def env():
    return "DATABASE_URL=postgres://x\nSECRET=abc"


@vuln_app.get("/{path:path}", response_class=HTMLResponse)
async def spa_fallback(path: str, request: Request):
    return "<html><body>" + "spa shell " * 20 + "</body></html>"


def scan_local(url: str):
    scanner = DynamicScanner(allow_private=True, budget_seconds=20)
    import backend.scanner.dynamic.engine as eng

    original = eng.GuardedTransport

    class LocalTransport(httpx.ASGITransport):
        def __init__(self, **_):
            super().__init__(app=vuln_app)

    eng.GuardedTransport = LocalTransport
    try:
        return run(scanner.scan(url)), scanner.warnings
    finally:
        eng.GuardedTransport = original


def test_dynamic_scan_detects_real_issues_without_soft404_noise():
    vulns, warnings = scan_local("http://testserver/?q=hi")
    titles = [v.title for v in vulns]
    assert any("Reflected XSS" in t for t in titles)
    assert any("Missing CSRF Token" in t for t in titles)
    assert any(".env" in t for t in titles)
    assert not any("/admin" in t or "/console" in t for t in titles), titles
    assert any("Plain HTTP" in t for t in titles)
    assert not any("Strict-Transport-Security" in t for t in titles)
    assert warnings == []


def test_dynamic_scan_detects_error_based_sqli():
    vulns, _ = scan_local("http://testserver/item?id=1")
    assert any(v.type == VulnType.SQLI for v in vulns)


def test_secret_evidence_is_masked():
    vulns = run(StaticScanner().scan('token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"', "t.py"))
    assert vulns and "abcdefghijklmnop" not in vulns[0].evidence


def test_flask_debug_is_critical():
    vulns = run(StaticScanner().scan("app.run(debug=True)", "a.py"))
    assert vulns[0].title == "Flask Debug Mode Enabled"


# --- dependencies, multi-file and repo scanning ---------------------------

import io as _io
import tarfile as _tarfile

from backend.scanner.repo import RepoError, fetch_repo, parse_repo
from backend.scanner.static.dependencies import DependencyScanner, parse_manifest


def osv_mock(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/querybatch":
        import json as _json
        queries = _json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "GHSA-test"}]} if q["package"]["name"] == "lodash" else {} for q in queries
        ]})
    return httpx.Response(200, json={
        "id": "GHSA-test", "summary": "Prototype Pollution", "aliases": ["CVE-2020-8203"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "lodash"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}],
    })


def mocked_dependency_scanner():
    return DependencyScanner(client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(osv_mock)))


def test_manifest_parsing():
    assert parse_manifest("Django==2.2.0\nflask>=1\nrequests[socks]==2.0.0 # pinned\n", "requirements.txt") == [
        ("PyPI", "django", "2.2.0", 1), ("PyPI", "requests", "2.0.0", 3)]
    npm = parse_manifest('{"dependencies": {"lodash": "^4.17.15", "x": "latest"}}', "package.json")
    assert [(e, n, v) for e, n, v, _ in npm] == [("npm", "lodash", "4.17.15")]
    assert parse_manifest("not json", "package.json") == []


def test_dependency_scan_reports_advisory_and_upgrade():
    scanner = StaticScanner(dependency_scanner=mocked_dependency_scanner())
    vulns = run(scanner.scan_files([("package.json", '{"dependencies": {"lodash": "4.17.15", "react": "19.0.0"}}')]))
    dep = [v for v in vulns if v.type == VulnType.VULNERABLE_COMPONENT]
    assert len(dep) == 1 and dep[0].severity.value == "HIGH"
    assert "4.17.19" in dep[0].description and "CVE-2020-8203" in dep[0].evidence


def test_dependency_lookup_failure_is_a_warning_not_an_error():
    def boom(_):
        raise httpx.ConnectError("down")
    scanner = StaticScanner(dependency_scanner=DependencyScanner(
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(boom))))
    vulns = run(scanner.scan_files([("requirements.txt", "django==2.2.0\n")]))
    assert vulns == [] and scanner.warnings


@pytest.mark.parametrize("target,expected", [
    ("https://github.com/Saumya039/PBL3", ("Saumya039", "PBL3", "HEAD")),
    ("github.com/a/b.git", ("a", "b", "HEAD")),
    ("https://github.com/a/b/tree/dev", ("a", "b", "dev")),
    ("a/b", ("a", "b", "HEAD")),
])
def test_parse_repo(target, expected):
    assert parse_repo(target) == expected


@pytest.mark.parametrize("target", ["https://gitlab.com/a/b", "http://127.0.0.1/a/b", "github.com/a/b/tree/../../x", "a"])
def test_parse_repo_rejects(target):
    with pytest.raises(RepoError):
        parse_repo(target)


def make_tarball(files: dict[str, bytes]) -> bytes:
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = _tarfile.TarInfo(f"repo-abc123/{name}")
            info.size = len(data)
            tar.addfile(info, _io.BytesIO(data))
    return buf.getvalue()


def test_fetch_repo_filters_files_in_memory():
    archive = make_tarball({
        "app.py": b'DEBUG = True\n',
        "node_modules/x/index.js": b"eval(x)",
        "logo.png": b"\x89PNG\x00\x00",
        "../../escape.py": b"os.system('x')",
        "bundle.min.js": b"eval(x)",
    })
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=archive)))
    snap = run(fetch_repo("github.com/a/b", client=client))
    names = [n for n, _ in snap.files]
    assert "app.py" in names
    assert not any("node_modules" in n or n.endswith((".png", ".min.js")) for n in names)
    assert all(not n.startswith("/") for n in names)


def test_fetch_repo_not_found():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(RepoError, match="not found"):
        run(fetch_repo("github.com/a/missing", client=client))


def test_files_endpoint():
    r = client.post("/api/scan/files", json={"files": [
        {"filename": "a.py", "content": "DEBUG = True"},
        {"filename": "b.js", "content": "el.innerHTML = x"},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["stats"]["files_scanned"] == 2 and body["target"] == "2 files"
    assert {v["location"] for v in body["vulnerabilities"]} == {"a.py:1", "b.js:1"}
    assert client.post("/api/scan/files", json={"files": []}).status_code == 422


def test_repo_endpoint_rejects_non_github():
    r = client.post("/api/scan/repo", json={"target": "http://169.254.169.254/"}, headers={"x-real-ip": "203.0.113.50"})
    assert r.status_code == 400


def test_forwarded_ip_is_ignored_without_trusted_proxy(monkeypatch):
    monkeypatch.delenv("VULNGUARD_TRUST_PROXY", raising=False)
    from backend.api.routes import client_ip
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (b"x-real-ip", b"203.0.113.99"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
    })
    assert client_ip(request) == "127.0.0.1"
