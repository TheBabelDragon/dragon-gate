"""Redirect Observatory — first fully functional user-facing experiment."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from dragon_gate.security.ssrf import SSRFProtection


class RedirectPolicy(str, Enum):
    INSPECT_ONLY = "INSPECT_ONLY"
    FOLLOW_SAFE = "FOLLOW_SAFE"
    SIMULATE = "SIMULATE"


REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class Hop:
    url: str
    status: int | None = None
    location: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    dns: list[str] = field(default_factory=list)
    error: str | None = None
    timing_ms: float | None = None
    tls: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InspectResult:
    start_url: str
    policy: str
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    loop_detected: bool = False
    downgrade_detected: bool = False
    hostname_changed: bool = False
    excessive_depth: bool = False
    error: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_url": self.start_url,
            "policy": self.policy,
            "hops": [h.to_dict() for h in self.hops],
            "final_url": self.final_url,
            "loop_detected": self.loop_detected,
            "downgrade_detected": self.downgrade_detected,
            "hostname_changed": self.hostname_changed,
            "excessive_depth": self.excessive_depth,
            "error": self.error,
            "evidence": self.evidence,
        }


class RedirectObservatory:
    def __init__(
        self,
        policy: RedirectPolicy = RedirectPolicy.INSPECT_ONLY,
        max_redirects: int = 10,
        timeout_s: float = 10.0,
        allow_private: bool = False,
        max_body: int = 64 * 1024,
    ) -> None:
        self.policy = policy
        self.max_redirects = max_redirects
        self.timeout_s = timeout_s
        self.ssrf = SSRFProtection(allow_private=allow_private)
        self.max_body = max_body

    def inspect(self, url: str) -> InspectResult:
        result = InspectResult(start_url=url, policy=self.policy.value)
        seen: set[str] = set()
        current = url
        start_scheme = urlparse(url).scheme
        start_host = urlparse(url).hostname

        try:
            self.ssrf.check_url(current)
        except ValueError as e:
            result.error = str(e)
            return result

        for depth in range(self.max_redirects + 1):
            if current in seen:
                result.loop_detected = True
                result.error = f"redirect loop detected at {current}"
                break
            seen.add(current)

            if depth >= self.max_redirects:
                result.excessive_depth = True
                result.error = f"exceeded max redirects ({self.max_redirects})"
                break

            hop = Hop(url=current)
            t0 = time.monotonic()
            try:
                # Always re-check SSRF (DNS rebinding protection)
                self.ssrf.check_url(current)
                with httpx.Client(
                    follow_redirects=False,
                    timeout=self.timeout_s,
                    verify=True,  # never disable cert verification
                    max_redirects=0,
                ) as client:
                    resp = client.request("GET", current)
                    hop.status = resp.status_code
                    hop.headers = {k: v for k, v in resp.headers.items()}
                    hop.location = resp.headers.get("location")
                    hop.timing_ms = (time.monotonic() - t0) * 1000

                    # Capture limited body for diagnostics only in SIMULATE
                    if self.policy == RedirectPolicy.SIMULATE:
                        _ = resp.content[: self.max_body]

            except httpx.ConnectError as e:
                hop.error = f"connect error: {e}"
                result.hops.append(hop)
                result.error = hop.error
                break
            except httpx.TimeoutException:
                hop.error = "timeout"
                result.hops.append(hop)
                result.error = hop.error
                break
            except Exception as e:
                hop.error = str(e)
                result.hops.append(hop)
                result.error = hop.error
                break

            result.hops.append(hop)

            if hop.status not in REDIRECT_CODES or not hop.location:
                result.final_url = current
                break

            next_url = urljoin(current, hop.location)
            next_parsed = urlparse(next_url)

            # Detect HTTPS downgrade
            if start_scheme == "https" and next_parsed.scheme == "http":
                result.downgrade_detected = True
                if self.policy != RedirectPolicy.SIMULATE:
                    result.error = "HTTPS downgrade detected — refusing to follow"
                    break

            # Hostname change
            if next_parsed.hostname and next_parsed.hostname != start_host:
                result.hostname_changed = True

            if self.policy == RedirectPolicy.INSPECT_ONLY:
                # Record the redirect but do not follow
                result.final_url = current
                hop.location = next_url  # absolute form
                break

            # FOLLOW_SAFE / SIMULATE continue
            try:
                self.ssrf.check_url(next_url)
            except ValueError as e:
                result.error = f"redirect target blocked: {e}"
                break

            current = next_url

        result.evidence = {
            "hop_count": len(result.hops),
            "statuses": [h.status for h in result.hops],
            "policy": self.policy.value,
        }
        return result

    def trace(self, url: str) -> InspectResult:
        """Follow safe redirects and produce a full chain."""
        old = self.policy
        self.policy = RedirectPolicy.FOLLOW_SAFE
        try:
            return self.inspect(url)
        finally:
            self.policy = old
