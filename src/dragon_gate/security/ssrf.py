"""SSRF protections: block loopback, private, link-local, multicast, metadata."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}


def is_blocked_destination(host: str, allow_private: bool = False) -> bool:
    host = host.lower().strip("[]")
    if host in METADATA_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # hostname — resolve for rebinding protection at connection time
        return False
    if allow_private:
        # still block loopback and metadata
        if addr.is_loopback or str(addr) in METADATA_HOSTS:
            return True
        return False
    for net in BLOCKED_NETWORKS:
        if addr in net:
            return True
    return False


class SSRFProtection:
    def __init__(self, allow_private: bool = False) -> None:
        self.allow_private = allow_private

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"scheme {parsed.scheme!r} not allowed")
        host = parsed.hostname
        if not host:
            raise ValueError("missing hostname")
        if is_blocked_destination(host, allow_private=self.allow_private):
            raise ValueError(f"destination blocked by SSRF policy: {host}")

    def check_resolved(self, host: str, resolved_ips: list[str]) -> None:
        """Re-validate after DNS to prevent rebinding."""
        if is_blocked_destination(host, allow_private=self.allow_private):
            raise ValueError(f"hostname blocked: {host}")
        for ip in resolved_ips:
            if is_blocked_destination(ip, allow_private=self.allow_private):
                raise ValueError(f"resolved address blocked (possible rebinding): {ip}")
