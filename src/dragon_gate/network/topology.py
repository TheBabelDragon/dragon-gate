"""Network topology view."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .gateways import Gateway
from .peers import Peer
from .routes import Route


@dataclass
class TopologyView:
    local_node_id: str
    peers: list[Peer] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    gateways: list[Gateway] = field(default_factory=list)
    internet_connected: bool | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "local_node_id": self.local_node_id,
            "peer_count": len(self.peers),
            "authenticated_peers": sum(
                1 for p in self.peers if p.trust.value in ("authenticated", "authorized")
            ),
            "route_count": len(self.routes),
            "gateway_count": len(self.gateways),
            "authorized_gateways": sum(1 for g in self.gateways if g.authorized),
            "internet_connected": self.internet_connected,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "local_node_id": self.local_node_id,
            "peers": [p.to_dict() for p in self.peers],
            "routes": [r.to_dict() for r in self.routes],
            "gateways": [g.to_dict() for g in self.gateways],
            "internet_connected": self.internet_connected,
            "summary": self.summary(),
        }
