"""Plugin / capability registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Capability:
    name: str
    version: str
    description: str
    privileged: bool = False
    offline_capable: bool = True
    handler: Callable[..., Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class CapabilityRegistry:
    def __init__(self) -> None:
        self._caps: dict[str, Capability] = {}

    def register(self, cap: Capability) -> None:
        self._caps[cap.name] = cap

    def get(self, name: str) -> Capability | None:
        return self._caps.get(name)

    def list(self) -> list[Capability]:
        return sorted(self._caps.values(), key=lambda c: c.name)

    def names(self) -> list[str]:
        return sorted(self._caps.keys())

    def report(self) -> list[dict[str, Any]]:
        return [
            {
                "name": c.name,
                "version": c.version,
                "description": c.description,
                "privileged": c.privileged,
                "offline_capable": c.offline_capable,
            }
            for c in self.list()
        ]


def build_default_registry() -> CapabilityRegistry:
    reg = CapabilityRegistry()
    for name, desc, offline in [
        ("identity", "Node identity generation and verification", True),
        ("evidence", "Structured evidence emission and verification", True),
        ("redirect-observatory", "HTTP redirect chain inspection", False),
        ("dns-lab", "DNS resolution laboratory", False),
        ("tls-lab", "TLS certificate laboratory", False),
        ("peers", "Peer registry and reachability", True),
        ("routes", "Route selection abstractions", True),
        ("gateways", "Gateway registry and health", True),
        ("aurora-adapter", "Aurora destination routing adapter", False),
    ]:
        reg.register(
            Capability(
                name=name,
                version="0.1.0",
                description=desc,
                offline_capable=offline,
            )
        )
    return reg
