"""Authenticated peer registry and reachability."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from dragon_gate.core.identity import verify_signed_identity


class TrustState(str, Enum):
    UNKNOWN = "unknown"
    DISCOVERED = "discovered"
    AUTHENTICATED = "authenticated"
    AUTHORIZED = "authorized"
    REVOKED = "revoked"


@dataclass
class Peer:
    node_id: str
    public_key: str
    trust: TrustState = TrustState.UNKNOWN
    last_seen: float = 0.0
    reachability: str = "unknown"  # reachable | unreachable | unknown
    capabilities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    signed_identity: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["trust"] = self.trust.value
        return d


class PeerRegistry:
    def __init__(self, require_auth: bool = True) -> None:
        self.require_auth = require_auth
        self._peers: dict[str, Peer] = {}

    def enroll(self, signed_identity: dict[str, Any], authorize: bool = False) -> Peer:
        """Replay-resistant enrollment: reject unsigned or invalid signatures."""
        if not verify_signed_identity(signed_identity):
            raise ValueError("peer authentication failure: invalid or missing signature")
        node_id = signed_identity["node_id"]
        public_key = signed_identity["public_key"]
        trust = TrustState.AUTHORIZED if authorize else TrustState.AUTHENTICATED
        peer = Peer(
            node_id=node_id,
            public_key=public_key,
            trust=trust,
            last_seen=time.time(),
            signed_identity=signed_identity,
            metadata=signed_identity.get("metadata", {}),
        )
        self._peers[node_id] = peer
        return peer

    def discover(self, node_id: str, public_key: str | None = None) -> Peer:
        """Untrusted discovery only — never elevates to authenticated."""
        if node_id in self._peers:
            p = self._peers[node_id]
            p.last_seen = time.time()
            return p
        peer = Peer(
            node_id=node_id,
            public_key=public_key or "",
            trust=TrustState.DISCOVERED,
            last_seen=time.time(),
        )
        self._peers[node_id] = peer
        return peer

    def get(self, node_id: str) -> Peer | None:
        return self._peers.get(node_id)

    def list(self) -> list[Peer]:
        return list(self._peers.values())

    def mark_reachability(self, node_id: str, state: str) -> None:
        if node_id in self._peers:
            self._peers[node_id].reachability = state
            self._peers[node_id].last_seen = time.time()
