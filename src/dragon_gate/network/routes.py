"""Route selection abstractions and provenance."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Route:
    destination: str
    next_hop: str
    gateway_id: str | None = None
    metric: int = 100
    source: str = "local"  # local | peer | aurora | static
    provenance: dict[str, Any] = field(default_factory=dict)
    last_updated: float = field(default_factory=time.time)
    healthy: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RouteTable:
    def __init__(self) -> None:
        self._routes: dict[str, Route] = {}

    def upsert(self, route: Route) -> None:
        key = f"{route.destination}|{route.next_hop}"
        self._routes[key] = route

    def select(self, destination: str) -> Route | None:
        candidates = [
            r for r in self._routes.values() if r.destination == destination and r.healthy
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda r: r.metric)

    def list(self) -> list[Route]:
        return list(self._routes.values())

    def mark_failed(self, destination: str, next_hop: str) -> None:
        key = f"{destination}|{next_hop}"
        if key in self._routes:
            self._routes[key].healthy = False
            self._routes[key].last_updated = time.time()

    def failover(self, destination: str) -> Route | None:
        """Return next-best healthy route after marking current preferred failed."""
        current = self.select(destination)
        if current:
            self.mark_failed(destination, current.next_hop)
        return self.select(destination)
