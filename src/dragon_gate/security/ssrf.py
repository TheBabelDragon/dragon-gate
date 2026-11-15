"""SSRF protections: address classification, resolution validation, fail-closed policy.

Central invariant: a destination is trusted only when the actual connection is
bound to an authorized, validated destination IP — not merely because a hostname
passed a URL-level check.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "metadata.azure.com",
    "instance-data",
}

# Always blocked even when allow_private=True
ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # unspecified / "this" network
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + metadata
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    ipaddress.ip_network("::/128"),  # unspecified
    ipaddress.ip_network("::1/128"),  # loopback
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("ff00::/8"),  # multicast
]

# RFC1918 + ULA — only permitted when allow_private=True
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),  # unique local
]


class SSRFError(ValueError):
    """Destination rejected by SSRF policy."""

    def __init__(self, message: str, *, reason: str = "blocked", detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.reason = reason
        self.detail = detail or {}


def normalize_hostname(host: str) -> str:
    """Normalize hostname: strip brackets, trailing dots, lower-case, IDNA."""
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        raise SSRFError("empty hostname", reason="malformed")
    # Reject userinfo-style leakage if present in host field
    if "@" in h or "/" in h or " " in h:
        raise SSRFError(f"malformed hostname: {host!r}", reason="malformed")
    try:
        # IDNA encode then decode to normalize internationalized names
        return h.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as e:
        raise SSRFError(f"invalid hostname encoding: {host!r}", reason="malformed") from e


def parse_ip(literal: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse IP literal; reject unusual representations that obscure destination."""
    s = literal.strip().strip("[]")
    # Reject IPv4-mapped forms with zone/scope in ambiguous ways later
    if "%" in s:
        # scoped addresses — reject for remote connections
        raise SSRFError(f"scoped address not allowed: {literal}", reason="scoped")
    try:
        return ipaddress.ip_address(s)
    except ValueError as e:
        raise SSRFError(f"invalid IP literal: {literal}", reason="malformed") from e


def classify_address(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str:
    """Return policy class for an address."""
    # Unwrap IPv4-mapped IPv6 for classification of the embedded v4
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return classify_address(addr.ipv4_mapped)

    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if str(addr) in METADATA_HOSTS or (
        isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("169.254.0.0/16")
    ):
        return "metadata"
    if addr.is_private:
        return "private"
    if not addr.is_global:
        return "non_global"
    return "global"


def is_always_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return is_always_blocked(addr.ipv4_mapped)
    for net in ALWAYS_BLOCKED_NETWORKS:
        if addr in net:
            return True
    cls = classify_address(addr)
    return cls in {
        "unspecified",
        "loopback",
        "link_local",
        "multicast",
        "reserved",
        "metadata",
        "non_global",
    }


def is_private_class(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return is_private_class(addr.ipv4_mapped)
    for net in PRIVATE_NETWORKS:
        if addr in net:
            return True
    return bool(addr.is_private) and not is_always_blocked(addr)


def is_blocked_destination(host: str, allow_private: bool = False) -> bool:
    """True if the destination host/IP must be rejected.

    Hostnames (non-literal) return False here; they must be resolved and
    validated via validate_resolved_addresses().
    """
    try:
        h = normalize_hostname(host)
    except SSRFError:
        return True
    if h in METADATA_HOSTS:
        return True
    try:
        addr = parse_ip(h)
    except SSRFError:
        return False  # not a literal — defer to resolution
    if is_always_blocked(addr):
        return True
    if is_private_class(addr) and not allow_private:
        return True
    return False


def validate_resolved_addresses(
    host: str,
    resolved_ips: list[str],
    *,
    allow_private: bool = False,
) -> list[str]:
    """Validate an entire DNS answer set. Fail closed.

    Rules:
    - Empty answer → reject
    - Any prohibited address → reject entire set (no mixed public/private)
    - allow_private only permits private classes, never loopback/link-local/etc.
    Returns the list of validated literal addresses (normalized).
    """
    if not resolved_ips:
        raise SSRFError(
            f"empty DNS answer for {host}",
            reason="empty_dns",
            detail={"host": host},
        )

    validated: list[str] = []
    classes: set[str] = set()
    for raw in resolved_ips:
        try:
            addr = parse_ip(raw)
        except SSRFError as e:
            raise SSRFError(
                f"malformed DNS answer for {host}: {raw}",
                reason="malformed_dns",
                detail={"host": host, "raw": raw},
            ) from e

        cls = classify_address(addr)
        classes.add(cls)

        if is_always_blocked(addr):
            raise SSRFError(
                f"resolved address blocked (possible rebinding): {addr} class={cls}",
                reason="rebinding" if cls in {"loopback", "private", "link_local", "metadata"} else "blocked",
                detail={"host": host, "address": str(addr), "class": cls},
            )

        if is_private_class(addr):
            if not allow_private:
                raise SSRFError(
                    f"resolved address blocked (possible rebinding): {addr} class=private",
                    reason="rebinding",
                    detail={"host": host, "address": str(addr), "class": "private"},
                )

        validated.append(str(addr))

    # Mixed public + private is never acceptable
    has_private = any(c == "private" for c in classes)
    has_global = any(c == "global" for c in classes)
    if has_private and has_global:
        raise SSRFError(
            f"mixed public/private DNS answers for {host} — rejected",
            reason="mixed_answers",
            detail={"host": host, "classes": sorted(classes), "addresses": validated},
        )

    return validated


@dataclass
class ResolutionResult:
    hostname: str
    addresses: list[str] = field(default_factory=list)
    family_hint: int | None = None  # socket.AF_INET / AF_INET6


def resolve_host(hostname: str, *,
    allow_private: bool = False,
    resolver: Any | None = None,
) -> ResolutionResult:
    """Resolve hostname with no long-lived cache; validate entire answer set.

    `resolver` may be a callable(hostname) -> list[str] for tests only.
    Production uses socket.getaddrinfo (system resolver, no app-level cache).
    """
    host = normalize_hostname(hostname)

    # Literal IP — no DNS
    try:
        addr = parse_ip(host)
        validated = validate_resolved_addresses(host, [str(addr)], allow_private=allow_private)
        return ResolutionResult(hostname=host, addresses=validated)
    except SSRFError as e:
        if e.reason == "malformed" and not _looks_like_ip(host):
            pass  # treat as hostname
        elif e.reason in {"blocked", "rebinding", "scoped", "malformed"} and _looks_like_ip(host):
            raise
        elif _looks_like_ip(host):
            raise

    if resolver is not None:
        raw_ips = list(resolver(host))
    else:
        raw_ips = _system_resolve(host)

    validated = validate_resolved_addresses(host, raw_ips, allow_private=allow_private)
    return ResolutionResult(hostname=host, addresses=validated)


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


def _system_resolve(hostname: str) -> list[str]:
    """Fresh getaddrinfo — no application DNS cache."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFError(f"DNS resolution failed for {hostname}: {e}", reason="dns_failure") from e
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


class SSRFProtection:
    def __init__(self, allow_private: bool = False, resolver: Any | None = None) -> None:
        self.allow_private = allow_private
        self._resolver = resolver  # test-only injectable

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise SSRFError(f"scheme {parsed.scheme!r} not allowed", reason="scheme")
        if parsed.username or parsed.password:
            raise SSRFError("URL userinfo/credentials not allowed", reason="userinfo")
        host = parsed.hostname
        if not host:
            raise SSRFError("missing hostname", reason="malformed")
        if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
            raise SSRFError(f"invalid port: {parsed.port}", reason="malformed")
        host_n = normalize_hostname(host)
        if is_blocked_destination(host_n, allow_private=self.allow_private):
            raise SSRFError(f"destination blocked by SSRF policy: {host_n}", reason="blocked")

    def check_resolved(self, host: str, resolved_ips: list[str]) -> list[str]:
        return validate_resolved_addresses(
            host, resolved_ips, allow_private=self.allow_private
        )

    def resolve(self, hostname: str) -> ResolutionResult:
        return resolve_host(
            hostname, allow_private=self.allow_private, resolver=self._resolver
        )
