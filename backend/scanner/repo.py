"""Download a public GitHub repository archive and collect scannable text files, in memory only."""

import io
import re
import tarfile
import zlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import httpx

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 150 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_TEXT_BYTES = 4 * 1024 * 1024
MAX_FILES = 600

GITHUB_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?"
    r"(?:/tree/([A-Za-z0-9._/-]{1,200}))?/?$"
)
SHORTHAND = re.compile(r"^([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})$")

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".next", "__pycache__", ".venv", "venv",
             "site-packages", "coverage", ".cache", "target", "bower_components"}
TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".go", ".java", ".kt",
                   ".cs", ".rs", ".swift", ".scala", ".sh", ".bash", ".sql", ".html", ".htm", ".vue", ".svelte",
                   ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties", ".tf", ".txt"}
TEXT_NAMES = {".env", "dockerfile", "procfile", ".htaccess", "web.config"}


class RepoError(ValueError):
    """User-facing problem with the requested repository."""


@dataclass
class RepoSnapshot:
    name: str
    files: list[tuple[str, str]] = field(default_factory=list)
    skipped: int = 0
    truncated: bool = False


def parse_repo(target: str) -> tuple[str, str, str]:
    target = target.strip()
    match = GITHUB_URL.match(target) or SHORTHAND.match(target)
    if not match:
        raise RepoError("Enter a public GitHub repository, like github.com/owner/repo")
    owner, repo = match.group(1), match.group(2)
    ref = match.group(3) if match.re is GITHUB_URL and match.group(3) else "HEAD"
    if ".." in ref:
        raise RepoError("Invalid branch name")
    return owner, repo, ref


def _wanted(path: PurePosixPath) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    name = path.name.lower()
    if name.endswith((".min.js", ".min.css", ".map")):
        return False
    return path.suffix.lower() in TEXT_EXTENSIONS or name in TEXT_NAMES or name.startswith(".env")


class _BoundedGunzip(io.RawIOBase):
    """Streams gzip data while enforcing a decompressed-size ceiling (zip-bomb guard)."""

    def __init__(self, data: bytes):
        self._src = io.BytesIO(data)
        self._dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._buf = b""
        self._total = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while not self._buf:
            chunk = self._src.read(64 * 1024)
            if not chunk:
                self._buf = self._dec.flush()
                if not self._buf:
                    return 0
                break
            self._buf = self._dec.decompress(chunk)
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        self._total += n
        if self._total > MAX_UNCOMPRESSED_BYTES:
            raise RepoError("Repository is too large to scan here. Use the CLI on a local checkout.")
        return n


async def fetch_repo(target: str, client: httpx.AsyncClient | None = None) -> RepoSnapshot:
    owner, repo, ref = parse_repo(target)
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(25.0, connect=8.0), follow_redirects=False)

    try:
        async with client.stream("GET", url, headers={"User-Agent": "VulnGuard/1.1"}) as resp:
            if resp.status_code == 404:
                raise RepoError("Repository or branch not found. Only public repositories can be scanned.")
            if resp.status_code != 200:
                raise RepoError(f"GitHub returned HTTP {resp.status_code} for this repository.")
            chunks, size = [], 0
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise RepoError("Repository archive is larger than 20 MB. Scan a local checkout with the CLI.")
                chunks.append(chunk)
    except httpx.HTTPError as exc:
        raise RepoError("Could not download the repository from GitHub.") from exc
    finally:
        if own_client:
            await client.aclose()

    snapshot = RepoSnapshot(name=f"{owner}/{repo}" + (f"@{ref}" if ref != "HEAD" else ""))
    total_text = 0
    try:
        with tarfile.open(fileobj=io.BufferedReader(_BoundedGunzip(b"".join(chunks))), mode="r|") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                # Archive entries are "<repo>-<sha>/path"; drop the root and never touch the filesystem
                path = PurePosixPath(*PurePosixPath(member.name).parts[1:])
                if not path.parts or not _wanted(path) or member.size > MAX_FILE_BYTES:
                    snapshot.skipped += 1
                    continue
                if len(snapshot.files) >= MAX_FILES or total_text + member.size > MAX_TOTAL_TEXT_BYTES:
                    snapshot.truncated = True
                    break
                handle = archive.extractfile(member)
                raw = handle.read(MAX_FILE_BYTES + 1) if handle else b""
                if b"\x00" in raw[:4096]:
                    snapshot.skipped += 1
                    continue
                total_text += len(raw)
                snapshot.files.append((str(path), raw.decode("utf-8", errors="replace")))
    except (tarfile.TarError, zlib.error, EOFError) as exc:
        raise RepoError("The repository archive could not be read.") from exc

    if not snapshot.files:
        raise RepoError("No scannable source files were found in this repository.")
    return snapshot
