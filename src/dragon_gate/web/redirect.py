"""Redirect Observatory — connection-boundary enforced hop validation."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from dragon_gate.evidence.schema import EvidenceEvent
from dragon_gate.evidence.store import EvidenceStore
from dragon_gate.security.pinned_transport import PinnedHTTPClient, PinnedResponse
from dragon_gate.security.ssrf import SSRFError, SSRFProtection


class RedirectPolicy(str, Enum):
    INSPECT_ONLY = "INSPECT_ONLY"
    FOLLOW_SAFE = "FOLLOW_SAFE"
    SIMULATE = "SIMULATE"


REDIRECT_CODES = {301, 302, 303, 307, 308}


def _redact_url(url: str) -> str:
    """Strip userinfo and other sensitive components for audit/logs."""
    p = urlparse(url)
    # Drop username/password
    host = p.hostname or ""
    if p.port:
        netloc = f"{host}:{p.port}"
    else:
        netloc = host
    return urlunparse((p.scheme, netloc, p.path or "/", "", p.query, ""))


@dataclass
class Hop:
    url: str
    status: int | None = None
    location: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    dns: list[str] = field(default_factory=list)
    connected_address: str | None = None
    error: str | None = None
    timing_ms: float | None = None
    tls: dict[str, Any] | None = None
    security_decision: str = "allow"  # allow | block
    rejection_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # never expose sensitive headers
        if d.get("headers"):
            d["headers"] = {
                k: v
                for k, v in d["headers"].items()
                if k.lower() not in {"authorization", "cookie", "set-cookie"}
            }
        d["url"] = _redact_url(d["url"]) if d.get("url") else d.get("url")
        return d


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
    evidence_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_url": _redact_url(self.start_url),
            "policy": self.policy,
            "hops": [h.to_dict() for h in self.hops],
            "final_url": _redact_url(self.final_url) if self.final_url else None,
            "loop_detected": self.loop_detected,
            "downgrade_detected": self.downgrade_detected,
            "hostname_changed": self.hostname_changed,
            "excessive_depth": self.excessive_depth,
            "error": self.error,
            "evidence": self.evidence,
            "evidence_event_ids": self.evidence_event_ids,
        }


class RedirectObservatory:
    def __init__(
        self,
        policy: RedirectPolicy = RedirectPolicy.INSPECT_ONLY,
        max_redirects: int = 10,
        timeout_s: float = 10.0,
        total_timeout_s: float | None = None,
        allow_private: bool = False,
        max_body: int = 64 * 1024,
        ssrf: SSRFProtection | None = None,
        evidence_store: EvidenceStore | None = None,
        node_id: str = "dg-local",
    ) -> None:
        self.policy = policy
        self.max_redirects = max_redirects
        self.timeout_s = timeout_s
        self.total_timeout_s = total_timeout_s or (timeout_s * max(1, max_redirects))
        self.ssrf = ssrf or SSRFProtection(allow_private=allow_private)
        self.max_body = max_body
        self.evidence_store = evidence_store
        self.node_id = node_id

    def _emit(self, event_type: str, observation: dict[str, Any]) -> str | None:
        if self.evidence_store is None:
            return None
        ev = EvidenceEvent(
            event_type=event_type,
            node_id=self.node_id,
            observation=observation,
            tool_identity="dragon-gate/0.2.0",
            provenance={"subsystem": "redirect-observatory"},
        )
        stored = self.evidence_store.append(ev)
        return stored.event_id

    def inspect(self, url: str) -> InspectResult:
        result = InspectResult(start_url=url, policy=self.policy.value)
        seen: set[str] = set()
        current = url
        start_scheme = urlparse(url).scheme
        start_host = urlparse(url).hostname
        started = time.monotonic()

        eid = self._emit(
            "web.redirect.inspect_started",
            {"url": _redact_url(url), "policy": self.policy.value},
        )
        if eid:
            result.evidence_event_ids.append(eid)

        try:
            self.ssrf.check_url(current)
        except SSRFError as e:
            result.error = str(e)
            eid = self._emit(
                "security.ssrf.blocked",
                {"url": _redact_url(current), "reason": e.reason, "detail": e.detail},
            )
            if eid:
                result.evidence_event_ids.append(eid)
            return result

        client = PinnedHTTPClient(
            ssrf=self.ssrf, timeout_s=self.timeout_s, max_body=self.max_body
        )

        # max_redirects = max number of *redirect transitions*
        # final destination still gets its own validation/connection
        for depth in range(self.max_redirects + 1):
            if time.monotonic() - started > self.total_timeout_s:
                result.error = "total inspection timeout exceeded"
                break

            canon = _redact_url(current)
            if canon in seen:
                result.loop_detected = True
                result.error = f"redirect loop detected at {canon}"
                eid = self._emit(
                    "security.redirect.loop_detected",
                    {"url": canon, "hop": depth},
                )
                if eid:
                    result.evidence_event_ids.append(eid)
                break
            seen.add(canon)

            if depth > self.max_redirects:
                result.excessive_depth = True
                result.error = f"exceeded max redirects ({self.max_redirects})"
                eid = self._emit(
                    "security.redirect.limit_exceeded",
                    {"limit": self.max_redirects, "hop": depth},
                )
                if eid:
                    result.evidence_event_ids.append(eid)
                break

            hop = Hop(url=current)
            try:
                # Independent validation for this hop
                self.ssrf.check_url(current)
                resp: PinnedResponse = client.request("GET", current)
                hop.status = resp.status_code
                hop.headers = resp.headers
                hop.location = resp.headers.get("location") or resp.headers.get("Location")
                hop.dns = list(resp.resolved_addresses)
                hop.connected_address = resp.connected_address
                hop.timing_ms = resp.timing_ms
                hop.security_decision = "allow"

                eid = self._emit(
                    "security.connection.destination_validated",
                    {
                        "url": _redact_url(current),
                        "connected_address": resp.connected_address,
                        "resolved_addresses": resp.resolved_addresses,
                        "hop": depth,
                    },
                )
                if eid:
                    result.evidence_event_ids.append(eid)

                eid = self._emit(
                    "web.redirect.hop_observed",
                    {
                        "url": _redact_url(current),
                        "status": hop.status,
                        "hop": depth,
                        "connected_address": hop.connected_address,
                    },
                )
                if eid:
                    result.evidence_event_ids.append(eid)

            except SSRFError as e:
                hop.error = str(e)
                hop.security_decision = "block"
                hop.rejection_reason = e.reason
                result.hops.append(hop)
                result.error = hop.error
                eid = self._emit(
                    "security.ssrf.blocked",
                    {
                        "url": _redact_url(current),
                        "reason": e.reason,
                        "detail": e.detail,
                        "hop": depth,
                    },
                )
                if eid:
                    result.evidence_event_ids.append(eid)
                if e.reason in {"rebinding", "mixed_answers"}:
                    eid = self._emit(
                        "security.dns.rebinding_detected",
                        {"url": _redact_url(current), "detail": e.detail, "hop": depth},
                    )
                    if eid:
                        result.evidence_event_ids.append(eid)
                break
            except (ConnectionError, TimeoutError, OSError) as e:
                hop.error = f"connect error: {e}"
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

            # Resolve relative Location
            try:
                next_url = urljoin(current, hop.location)
            except Exception:
                result.error = "invalid Location header"
                break

            next_parsed = urlparse(next_url)
            if next_parsed.scheme not in ("http", "https"):
                result.error = f"unsupported redirect scheme: {next_parsed.scheme!r}"
                hop.security_decision = "block"
                hop.rejection_reason = "scheme"
                break
            if not next_parsed.hostname:
                result.error = "redirect missing hostname"
                break

            # HTTPS downgrade detection (any hop)
            if start_scheme == "https" and next_parsed.scheme == "http":
                result.downgrade_detected = True
                eid = self._emit(
                    "security.redirect.downgrade_blocked",
                    {"from": _redact_url(current), "to": _redact_url(next_url), "hop": depth},
                )
                if eid:
                    result.evidence_event_ids.append(eid)
                if self.policy != RedirectPolicy.SIMULATE:
                    result.error = "HTTPS downgrade detected — refusing to follow"
                    break

            if next_parsed.hostname and start_host and next_parsed.hostname != start_host:
                result.hostname_changed = True

            if self.policy == RedirectPolicy.INSPECT_ONLY:
                result.final_url = current
                hop.location = next_url
                break

            # FOLLOW_SAFE / SIMULATE: validate next before following
            try:
                self.ssrf.check_url(next_url)
            except SSRFError as e:
                result.error = f"redirect target blocked: {e}"
                eid = self._emit(
                    "security.ssrf.blocked",
                    {
                        "url": _redact_url(next_url),
                        "reason": e.reason,
                        "detail": e.detail,
                        "hop": depth + 1,
                    },
                )
                if eid:
                    result.evidence_event_ids.append(eid)
                break

            current = next_url
        else:
            # exhausted loop without break on final non-redirect — depth limit
            if not result.final_url and not result.error:
                result.excessive_depth = True
                result.error = f"exceeded max redirects ({self.max_redirects})"

        result.evidence = {
            "hop_count": len(result.hops),
            "statuses": [h.status for h in result.hops],
            "policy": self.policy.value,
            "connected_addresses": [h.connected_address for h in result.hops],
        }
        return result

    def trace(self, url: str) -> InspectResult:
        old = self.policy
        self.policy = RedirectPolicy.FOLLOW_SAFE
        try:
            return self.inspect(url)
        finally:
            self.policy = old
