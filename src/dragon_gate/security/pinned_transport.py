"""Connection-pinned HTTP client.

Lifecycle per request:
  1. Parse URL / scheme / hostname
  2. Fresh DNS resolution (no app-level cache)
  3. Validate entire A/AAAA set (fail closed on any prohibited address)
  4. Connect TCP to a validated literal only
  5. TLS wrap with server_hostname = original hostname (SNI + cert verify)
  6. Send Host: original hostname

Never disable certificate verification.
Never allow a second uncontrolled DNS lookup between validation and connect.
"""

from __future__ import annotations

import asyncio
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": {k: v for k, v in self.headers.items()
                        if k.lower() not in {"authorization", "cookie", "set-cookie"}},
            "url": self.url,
            "resolved_addresses": self.resolved_addresses,
            "connected_address": self.connected_address,
            "timing_ms": self.timing_ms,
            "error": self.error,
            "body_len": len(self.content),
        }


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a literal IP but uses SNI/cert name = hostname."""

    def __init__(
        self,
        connect_ip: str,
        server_hostname: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        # host passed to parent is used for default SNI; we override connect()
        super().__init__(
            server_hostname,
            port=port,
            timeout=timeout,
            context=context,
        )
        self._connect_ip = connect_ip
        self._server_hostname = server_hostname

    def connect(self) -> None:
        sock = socket.create_connection((self._connect_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(
                sock, server_hostname=self._server_hostname
            )
        except Exception:
            sock.close()
            raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, connect_ip: str, port: int, timeout: float) -> None:
        super().__init__(connect_ip, port=port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout)


class PinnedHTTPClient:
    """Synchronous HTTP client with connection-level SSRF enforcement."""

    def __init__(
        self,
        ssrf: SSRFProtection | None = None,
        timeout_s: float = 10.0,
        max_body: int = 64 * 1024,
    ) -> None:
        self.ssrf = ssrf or SSRFProtection()
        self.timeout_s = timeout_s
        self.max_body = max_body

    def request(self, method: str, url: str) -> PinnedResponse:
        t0 = time.monotonic()
        self.ssrf.check_url(url)
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise SSRFError("missing hostname", reason="malformed")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        resolution = self.ssrf.resolve(hostname)
        if not resolution.addresses:
            raise SSRFError("no validated addresses", reason="empty_dns")

        last_error: Exception | None = None
        for ip in resolution.addresses:
            try:
                return self._connect_one(
                    method=method,
                    url=url,
                    scheme=parsed.scheme,
                    hostname=hostname,
                    ip=ip,
                    port=port,
                    path=path,
                    resolution=resolution,
                    t0=t0,
                )
            except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as e:
                last_error = e
                continue

        raise ConnectionError(
            f"all validated addresses failed for {hostname}: {last_error}"
        )

    def _connect_one(
        self,
        *,
        method: str,
        url: str,
        scheme: str,
        hostname: str,
        ip: str,
        port: int,
        path: str,
        resolution: ResolutionResult,
        t0: float,
    ) -> PinnedResponse:
        conn: http.client.HTTPConnection
        if scheme == "https":
            ctx = ssl.create_default_context()
            # Certificate verification stays ON; SNI + verify name = original hostname
            conn = _PinnedHTTPSConnection(
                connect_ip=ip,
                server_hostname=hostname,
                port=port,
                timeout=self.timeout_s,
                context=ctx,
            )
        else:
            conn = _PinnedHTTPConnection(connect_ip=ip, port=port, timeout=self.timeout_s)

        try:
            conn.request(method, path, headers={"Host": hostname, "Connection": "close"})
            resp = conn.getresponse()
            # Bounded body
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total <= self.max_body:
                    chunks.append(chunk)
                if total > self.max_body:
                    # stop reading further — bound enforced
                    break
            body = b"".join(chunks)[: self.max_body]
            headers = {k: v for k, v in resp.getheaders()}
            status = resp.status
        finally:
            conn.close()

        return PinnedResponse(
            status_code=status,
            headers=headers,
            content=body,
            url=url,
            resolved_addresses=list(resolution.addresses),
            connected_address=ip,
            timing_ms=(time.monotonic() - t0) * 1000,
        )


class AsyncPinnedHTTPClient:
    """Async wrapper for dashboard integration (executor-backed)."""

    def __init__(
        self,
        ssrf: SSRFProtection | None = None,
        timeout_s: float = 10.0,
        max_body: int = 64 * 1024,
    ) -> None:
        self._sync = PinnedHTTPClient(ssrf=ssrf, timeout_s=timeout_s, max_body=max_body)

    async def request(self, method: str, url: str) -> PinnedResponse:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._sync.request(method, url))


def make_test_ssrf(
    answers: dict[str, list[str]],
    *,
    allow_private: bool = False,
) -> SSRFProtection:
    """Test helper: inject DNS answers. Does not weaken production policy."""

    def resolver(hostname: str) -> list[str]:
        key = hostname.lower().rstrip(".")
        if key not in answers:
            raise SSRFError(f"DNS resolution failed for {hostname}", reason="dns_failure")
        return list(answers[key])

    return SSRFProtection(allow_private=allow_private, resolver=resolver)
