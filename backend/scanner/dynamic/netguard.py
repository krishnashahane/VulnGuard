"""Outbound request guard for the dynamic scanner.

The scanner fetches user-supplied URLs, so it is itself an SSRF vector. Every
request (including each redirect hop) passes through GuardedTransport, which
refuses non-public destinations and caps how much of a response body is read.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

import httpx

MAX_BODY_BYTES = 2 * 1024 * 1024
ALLOWED_SCHEMES = {"http", "https"}


class UnsafeTargetError(ValueError):
    """Raised when a URL points somewhere the scanner must not reach."""


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def assert_public_host(host: str, port: int) -> None:
    host = host.strip("[]")
    if not host:
        raise UnsafeTargetError("URL has no host")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [literal]
    else:
        if host.lower() == "localhost" or host.lower().endswith((".localhost", ".local", ".internal")):
            raise UnsafeTargetError("Internal hostnames cannot be scanned")
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeTargetError(f"Could not resolve host '{host}'") from exc
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]

    if not addresses or not all(_is_public(ip) for ip in addresses):
        raise UnsafeTargetError("Target resolves to a private, loopback or reserved address")


async def validate_target_url(url: str) -> str:
    """Normalise a user-supplied URL and ensure it points at a public host."""
    url = url.strip()
    if not url:
        raise UnsafeTargetError("Target URL is required")
    if "://" not in url:
        url = f"https://{url}"
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeTargetError("Only http and https URLs are supported")
    if parts.username or parts.password:
        raise UnsafeTargetError("URLs with embedded credentials are not allowed")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise UnsafeTargetError("Invalid port") from exc
    await assert_public_host(parts.hostname or "", port)
    return url


class _CappedStream(httpx.AsyncByteStream):
    def __init__(self, inner: httpx.AsyncByteStream, limit: int):
        self._inner = inner
        self._limit = limit

    async def __aiter__(self):
        remaining = self._limit
        async for chunk in self._inner:
            if remaining <= 0:
                break
            yield chunk[:remaining]
            remaining -= len(chunk)

    async def aclose(self) -> None:
        await self._inner.aclose()


class GuardedTransport(httpx.AsyncBaseTransport):
    def __init__(self, max_body: int = MAX_BODY_BYTES, allow_private: bool = False, **kwargs):
        self._inner = httpx.AsyncHTTPTransport(trust_env=False, **kwargs)
        self._max_body = max_body
        self._allow_private = allow_private

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme not in ALLOWED_SCHEMES:
            raise httpx.UnsupportedProtocol(f"Blocked scheme: {request.url.scheme}")
        key = (request.url.host, request.url.port or (443 if request.url.scheme == "https" else 80))
        if not self._allow_private:
            try:
                await assert_public_host(*key)
            except UnsafeTargetError as exc:
                raise httpx.ConnectError(str(exc), request=request) from exc

        response = await self._inner.handle_async_request(request)
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_CappedStream(response.stream, self._max_body),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()
