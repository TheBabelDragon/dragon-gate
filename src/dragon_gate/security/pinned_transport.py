"""Connection-pinned HTTP client.

Resolve → validate entire address set → connect to validated literal only.
Preserve original hostname for Host header, TLS SNI, and certificate verification.
Never disable certificate verification. Never allow a second uncontrolled DNS lookup.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import httpx

from dragon_gate.security.ssrf import ResolutionResult, SSRFError, SSRFProtection


@dataclass
class PinnedResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes
    url: str
    resolved_addresses: list[str] = field(default_factory=list)
    connected_address: str | None = None
    timing_ms: float | None = None
    error: str | None = None


def _build_ssl_context(server_hostname: str, verify: bool = True) -> ssl.SSLContext:
    if not verify:
        raise RuntimeError("TLS verification cannot be disabled")
    ctx = ssl.create_default_context()
    # hostname checking is performed against server_hostname at wrap time
    return ctx


def _rewrite_url_to_ip(url: str, ip: str) -> str:
    """Replace hostname with literal IP while keeping path/query/fragment."""
    p = urlparse(url)
    # Bracket IPv6 literals
    host = f"[{ip}]" if ":" in ip else ip
    netloc = host
    if p.port:
        netloc = f"{host}:{p.port}"
    elif p.scheme == "https":
        pass  # default 443
    elif p.scheme == "http":
        pass  # default 80
    # Preserve explicit port from original if present in netloc
    if p.port:
        netloc = f"{host}:{p.port}"
    return urlunparse((p.scheme, netloc, p.path or "/", p.params, p.query, p.fragment))


class PinnedHTTPClient:
    """Synchronous HTTP client with connection-level SSRF enforcement."""

    def __init__(
        self,
        ssrf: SSRFProtection | None = None,
        timeout_s: float = 10.0,
        max_body: int = 64 * 1024,
        verify_tls: bool = True,
    ) -> None:
        if not verify_tls:
            raise RuntimeError("TLS verification cannot be disabled")
        self.ssrf = ssrf or SSRFProtection()
        self.timeout_s = timeout_s
        self.max_body = max_body

    def request(self, method: str, url: str) -> PinnedResponse:
        import time

        t0 = time.monotonic()
        self.ssrf.check_url(url)
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise SSRFError("missing hostname", reason="malformed")

        resolution = self.ssrf.resolve(hostname)
        if not resolution.addresses:
            raise SSRFError("no validated addresses", reason="empty_dns")

        last_error: Exception | None = None
        for ip in resolution.addresses:
            try:
                return self._connect_pinned(
                    method, url, hostname, ip, resolution, t0
                )
            except (httpx.ConnectError, httpx.ConnectTimeout, OSError) as e:
                last_error = e
                continue

        raise httpx.ConnectError(
            f"all validated addresses failed for {hostname}: {last_error}"
        )

    def _connect_pinned(
        self,
        method: str,
        url: str,
        hostname: str,
        ip: str,
        resolution: ResolutionResult,
        t0: float,
    ) -> PinnedResponse:
        import time

        pinned_url = _rewrite_url_to_ip(url, ip)
        headers = {"Host": hostname}

        # Force httpcore/httpx to use the literal IP with SNI = original hostname.
        # Using transport mounted to the IP URL ensures no second DNS lookup.
        timeout = httpx.Timeout(self.timeout_s)

        with httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            verify=True,
            trust_env=False,  # ignore HTTP_PROXY etc. for security boundary
        ) as client:
            # httpx connects to the IP in pinned_url; we set Host for virtual hosting.
            # For HTTPS, we must set extensions server_name so SNI/cert match hostname.
            extensions: dict[str, Any] = {}
            # httpx 0.27+ uses request extensions for SNI when URL host is an IP:
            # pass headers Host and use the "sni_hostname" pattern via mounts.

            resp = client.request(
                method,
                pinned_url,
                headers=headers,
                extensions={"sni_hostname": hostname} if urlparse(url).scheme == "https" else {},
            )
            body = resp.content[: self.max_body]
            # Consume/close residual
            resp.close()

            return PinnedResponse(
                status_code=resp.status_code,
                headers={k: v for k, v in resp.headers.items()},
                content=body,
                url=url,
                resolved_addresses=list(resolution.addresses),
                connected_address=ip,
                timing_ms=(time.monotonic() - t0) * 1000,
            )


class AsyncPinnedHTTPClient:
    """Async counterpart for dashboard / future integration."""

    def __init__(
        self,
        ssrf: SSRFProtection | None = None,
        timeout_s: float = 10.0,
        max_body: int = 64 * 1024,
    ) -> None:
        self.ssrf = ssrf or SSRFProtection()
        self.timeout_s = timeout_s
        self.max_body = max_body

    async def request(self, method: str, url: str) -> PinnedResponse:
        # Run sync pinning in executor for now; full aiohttp resolver can replace later.
        loop = asyncio.get_event_loop()
        client = PinnedHTTPClient(
            ssrf=self.ssrf, timeout_s=self.timeout_s, max_body=self.max_body
        )
        return await loop.run_in_executor(None, lambda: client.request(method, url))


def make_test_ssrf(
    answers: dict[str, list[str]],
    *,
    allow_private: bool = False,
) -> SSRFProtection:
    """Test helper: inject fixed DNS answers without loopback policy bypass."""

    def resolver(hostname: str) -> list[str]:
        key = hostname.lower().rstrip(".")
        if key not in answers:
            raise SSRFError(f"DNS resolution failed for {hostname}", reason="dns_failure")
        return list(answers[key])

    return SSRFProtection(allow_private=allow_private, resolver=resolver)
