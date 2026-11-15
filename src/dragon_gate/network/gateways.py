"""Gateway registry, health, and authorization."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class GatewayState(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    COOLDOWN = "cooldown"


@dataclass
class Gateway:
    gateway_id: str
    endpoint: str
    authorized: bool = False
    state: GatewayState = GatewayState.UNKNOWN
    last_check: float = 0.0
    cooldown_until: float = 0.0
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    def in_cooldown(self) -> bool:
        return time.time() < self.cooldown_until


class GatewayRegistry:
    def __init__(self) -> None:
        self._gateways: dict[str, Gateway] = {}

    def register(self, gw: Gateway) -> None:
        self._gateways[gw.gateway_id] = gw

    def get(self, gateway_id: str) -> Gateway | None:
        return self._gateways.get(gateway_id)

    def list(self) -> list[Gateway]:
        return list(self._gateways.values())

    def authorize(self, gateway_id: str) -> None:
        if gateway_id in self._gateways:
            self._gateways[gateway_id].authorized = True

    def set_state(self, gateway_id: str, state: GatewayState, cooldown_s: float = 0) -> None:
        if gateway_id not in self._gateways:
            return
        gw = self._gateways[gateway_id]
        gw.state = state
        gw.last_check = time.time()
        if cooldown_s > 0:
            gw.cooldown_until = time.time() + cooldown_s
            gw.state = GatewayState.COOLDOWN

    def select_authorized(self) -> Gateway | None:
        candidates = [
            g
            for g in self._gateways.values()
            if g.authorized and g.state in (GatewayState.HEALTHY, GatewayState.UNKNOWN)
            and not g.in_cooldown()
        ]
        return candidates[0] if candidates else None
