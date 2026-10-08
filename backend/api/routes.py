import time
from collections import OrderedDict, defaultdict, deque

from fastapi import APIRouter, HTTPException, Request

from ..scanner.models import MAX_TOTAL_BYTES, FilesScanRequest, RepoScanRequest, ScanRequest, ScanResult, utcnow
from ..scanner.dynamic.engine import DynamicScanner
from ..scanner.dynamic.netguard import UnsafeTargetError, validate_target_url
from ..scanner.static.engine import StaticScanner
from ..scanner.repo import RepoError, fetch_repo
from ..patcher.engine import PatchEngine

VERSION = "1.1.0"
MAX_STORED_SCANS = 200

router = APIRouter(prefix="/api")

patch_engine = PatchEngine()


class ScanStore:
    """Bounded in-memory LRU. Serverless instances are ephemeral; the client keeps its own history."""

    def __init__(self, capacity: int):
        self.capacity = capacity
        self._items: OrderedDict[str, ScanResult] = OrderedDict()

    def put(self, result: ScanResult) -> None:
        self._items[result.id] = result
        self._items.move_to_end(result.id)
        while len(self._items) > self.capacity:
            self._items.popitem(last=False)

    def get(self, scan_id: str) -> ScanResult | None:
        return self._items.get(scan_id)


class RateLimiter:
    """Sliding-window limiter keyed by client IP (best effort per instance)."""

    def __init__(self, limit: int, window: float):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            retry = int(self.window - (now - hits[0])) + 1
            raise HTTPException(
                status_code=429,
                detail="Too many scans. Please wait a moment and try again.",
                headers={"Retry-After": str(retry)},
            )
        hits.append(now)
        if len(self._hits) > 10_000:
            self._hits = defaultdict(deque, {k: v for k, v in self._hits.items() if v})


scan_store = ScanStore(MAX_STORED_SCANS)
dynamic_limiter = RateLimiter(limit=6, window=60)
static_limiter = RateLimiter(limit=30, window=60)
repo_limiter = RateLimiter(limit=5, window=60)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def finalize(result: ScanResult, vulns, warnings: list[str] | None = None, stats: dict | None = None) -> ScanResult:
    result.vulnerabilities = vulns
    result.patches = patch_engine.generate_patches(vulns)
    result.warnings = warnings or []
    result.stats = stats or {}
    result.completed_at = utcnow()
    result.compute_summary()
    scan_store.put(result)
    return result


@router.get("/health")
async def health():
    return {"status": "ok", "service": "VulnGuard", "version": VERSION}


@router.post("/scan/dynamic", response_model=ScanResult)
async def run_dynamic_scan(body: ScanRequest, request: Request):
    dynamic_limiter.check(client_ip(request))
    if len(body.target) > 2048:
        raise HTTPException(status_code=422, detail="URL is too long")

    try:
        target = await validate_target_url(body.target)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scanner = DynamicScanner()
    result = ScanResult(target=target, scan_type="dynamic")
    try:
        vulns = await scanner.scan(target)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="The scan could not be completed against this target.") from exc
    return finalize(result, vulns, scanner.warnings)


async def run_static(result: ScanResult, files: list[tuple[str, str]], stats: dict | None = None) -> ScanResult:
    scanner = StaticScanner()
    try:
        vulns = await scanner.scan_files(files)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Analysis failed.") from exc
    return finalize(result, vulns, scanner.warnings, {"files_scanned": len(files), **(stats or {})})


@router.post("/scan/static", response_model=ScanResult)
async def run_static_scan(body: ScanRequest, request: Request):
    static_limiter.check(client_ip(request))
    filename = (body.filename or "snippet").strip()[:255] or "snippet"
    return await run_static(ScanResult(target=filename, scan_type="static"), [(filename, body.target)])


@router.post("/scan/files", response_model=ScanResult)
async def run_files_scan(body: FilesScanRequest, request: Request):
    static_limiter.check(client_ip(request))
    if sum(len(f.content) for f in body.files) > MAX_TOTAL_BYTES:
        raise HTTPException(status_code=422, detail="Files exceed the 2 MB total limit.")
    files = [(f.filename.strip().lstrip("/")[:255] or "file", f.content) for f in body.files]
    label = files[0][0] if len(files) == 1 else f"{len(files)} files"
    return await run_static(ScanResult(target=label, scan_type="static"), files)


@router.post("/scan/repo", response_model=ScanResult)
async def run_repo_scan(body: RepoScanRequest, request: Request):
    repo_limiter.check(client_ip(request))
    try:
        snapshot = await fetch_repo(body.target)
    except RepoError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = await run_static(
        ScanResult(target=f"github.com/{snapshot.name}", scan_type="repo"),
        snapshot.files,
        {"files_skipped": snapshot.skipped},
    )
    if snapshot.truncated:
        result.warnings.append("Repository was larger than the scan limit; only the first files were analysed")
    return result


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    result = scan_store.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result
