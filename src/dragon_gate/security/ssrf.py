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

ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


class SSRFError(ValueError):
    """Destination rejected by SSRF policy."""

    def __init__(
        self,
        message: str,
        *,
        reason: str = "blocked",
        detail: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.reason = reason
        self.detail = detail or {}


def normalize_hostname(host: str) -> str:
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        raise SSRFError("empty hostname", reason="malformed")
    if "@" in h or "/" in h or " " in h:
        raise SSRFError(f"malformed hostname: {host!r}", reason="malformed")
    try:
        return h.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as e:
        raise SSRFError(f"invalid hostname encoding: {host!r}", reason="malformed") from e


def parse_ip(literal: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    s = literal.strip().strip("[]")
    if "%" in s:
        raise SSRFError(f"scoped address not allowed: {literal}", reason="scoped")
    try:
        return ipaddress.ip_address(s)
    except ValueError as e:
        raise SSRFError(f"invalid IP literal: {literal}", reason="malformed") from e


def classify_address(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str:
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
        isinstance(addr, ipaddress.IPv4Address)
        and addr in ipaddress.ip_network("169.254.0.0/16")
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
    try:
        h = normalize_hostname(host)
    except SSRFError:
        return True
    if h in METADATA_HOSTS:
        return True
    try:
        addr = parse_ip(h)
    except SSRFError:
        return False
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

    Ordering:
    1. Parse all answers (malformed → reject).
    2. Classify the full set.
    3. If mixed public+private → mixed_answers (before single-address raise).
    4. Reject any always-blocked or unauthorized private address.
    """
    if not resolved_ips:
        raise SSRFError(
            f"empty DNS answer for {host}",
            reason="empty_dns",
            detail={"host": host},
        )

    parsed: list[tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address, str]] = []
    for raw in resolved_ips:
        try:
            addr = parse_ip(raw)
        except SSRFError as e:
            raise SSRFError(
                f"malformed DNS answer for {host}: {raw}",
                reason="malformed_dns",
                detail={"host": host, "raw": raw},
            ) from e
        parsed.append((str(addr), addr, classify_address(addr)))

    classes = {cls for _, _, cls in parsed}
    has_private = "private" in classes
    has_global = "global" in classes

    # Prefer the mixed-answer diagnostic when both classes appear
    if has_private and has_global and not allow_private:
        raise SSRFError(
            f"mixed public/private DNS answers for {host} — rejected",
            reason="mixed_answers",
            detail={
                "host": host,
                "classes": sorted(classes),
                "addresses": [a for a, _, _ in parsed],
            },
        )

    validated: list[str] = []
    for addr_s, addr, cls in parsed:
        if is_always_blocked(addr):
            raise SSRFError(
                f"resolved address blocked (possible rebinding): {addr} class={cls}",
                reason=(
                    "rebinding"
                    if cls in {"loopback", "private", "link_local", "metadata"}
                    else "blocked"
                ),
                detail={"host": host, "address": addr_s, "class": cls},
            )

        if is_private_class(addr) and not allow_private:
            raise SSRFError(
                f"resolved address blocked (possible rebinding): {addr} class=private",
                reason="rebinding",
                detail={"host": host, "address": addr_s, "class": "private"},
            )

        validated.append(addr_s)

    # When allow_private, still forbid mixing private with global
    if has_private and has_global:
        raise SSRFError(
            f"mixed public/private DNS answers for {host} — rejected",
            reason="mixed_answers",
            detail={
                "host": host,
                "classes": sorted(classes),
                "addresses": validated,
            },
        )

    return validated


@dataclass
class ResolutionResult:
    hostname: str
    addresses: list[str] = field(default_factory=list)
    family_hint: int | None = None


def resolve_host(
    hostname: str,
    *,
    allow_private: bool = False,
    resolver: Any | None = None,
) -> ResolutionResult:
    host = normalize_hostname(hostname)

    if _looks_like_ip(host):
        addr = parse_ip(host)
        validated = validate_resolved_addresses(
            host, [str(addr)], allow_private=allow_private
        )
        return ResolutionResult(hostname=host, addresses=validated)

    if resolver is not None:
        raw_ips = list(resolver(host))
    else:
        raw_ips = _system_resolve(host)

    validated = validate_resolved_addresses(
        host, raw_ips, allow_private=allow_private
    )
    return ResolutionResult(hostname=host, addresses=validated)


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


def _system_resolve(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFError(
            f"DNS resolution failed for {hostname}: {e}", reason="dns_failure"
        ) from e
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


class SSRFProtection:
    def __init__(self, allow_private: bool = False, resolver: Any | None = None) -> None:
        self.allow_private = allow_private
        self._resolver = resolver

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
            raise SSRFError(
                f"destination blocked by SSRF policy: {host_n}", reason="blocked"
            )

    def check_resolved(self, host: str, resolved_ips: list[str]) -> list[str]:
        return validate_resolved_addresses(
            host, resolved_ips, allow_private=self.allow_private
        )

    def resolve(self, hostname: str) -> ResolutionResult:
        return resolve_host(
            hostname, allow_private=self.allow_private, resolver=self._resolver
        )
