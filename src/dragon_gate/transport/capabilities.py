"""Transport capability and link-quality reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class TransportCapability:
    name: str
    kind: str  # ethernet | wifi | wireguard | cellular | optical | radio | other
    available: bool
    ipv4: bool = False
    ipv6: bool = False
    encrypted: bool = False
    privileged: bool = False
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def report_transport_capabilities() -> list[TransportCapability]:
    """Best-effort local transport inventory (no root required)."""
    caps: list[TransportCapability] = [
        TransportCapability(
            name="ipv4",
            kind="other",
            available=True,
            ipv4=True,
            notes="IPv4 stack present",
        ),
        TransportCapability(
            name="ipv6",
            kind="other",
            available=True,
            ipv6=True,
            notes="IPv6 stack present (may be disabled)",
        ),
        TransportCapability(
            name="wireguard",
            kind="wireguard",
            available=False,  # integration boundary only in v0.1
            encrypted=True,
            privileged=True,
            notes="WireGuard integration boundary — not auto-configured in v0.1",
        ),
        TransportCapability(
            name="quic-experiment",
            kind="other",
            available=False,
            encrypted=True,
            notes="QUIC transport experiments planned",
        ),
    ]
    return caps
