"""NodeRuntime — authenticated multi-node control plane."""

from __future__ import annotations

import asyncio
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from dragon_gate.core.identity import NodeIdentity, load_or_create_identity
from dragon_gate.network.peers import TrustState
from dragon_gate.runtime.protocol import (
    MsgType,
    make_challenge,
    make_hello,
    make_response,
    validate_hello,
    verify_response,
)
from dragon_gate.runtime.store import PeerStore
from dragon_gate.runtime.transport import FramedConnection, ProtocolError, connect_tcp, start_server

DEFAULT_CAPABILITIES = [
    "gate-core",
    "gate-peer",
    "gate-security",
    "gate-evidence",
]


class Reachability:
    UNKNOWN = "unknown"
    REACHABLE = "reachable"
    STALE = "stale"
    UNREACHABLE = "unreachable"


class NodeRuntime:
    def __init__(
        self,
        *,
        data_dir: Path | str | None = None,
        identity: NodeIdentity | None = None,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        heartbeat_interval_s: float = 5.0,
        heartbeat_timeout_s: float = 15.0,
        max_connections: int = 32,
        capabilities: list[str] | None = None,
        evidence_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir) if data_dir else Path.home() / ".local/share/dragon-gate"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        id_path = self.data_dir / "identity.json"
        self.identity = identity or load_or_create_identity(id_path)
        self.store = PeerStore(self.data_dir / "peers.db")
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.heartbeat_interval_s = heartbeat_interval_s
        self.heartbeat_timeout_s = heartbeat_timeout_s
        self.max_connections = max_connections
        self.capabilities = capabilities or list(DEFAULT_CAPABILITIES)
        self._evidence = evidence_callback
        self._server: asyncio.AbstractServer | None = None
        self._sessions: dict[str, FramedConnection] = {}
        self._hb_seq = 0
        self._tasks: list[asyncio.Task] = []
        self._running = False

    @property
    def node_id(self) -> str:
        return self.identity.node_id

    def _emit(self, event_type: str, observation: dict[str, Any]) -> None:
        if self._evidence:
            self._evidence(event_type, observation)

    async def start(self) -> tuple[str, int]:
        if self._running:
            return self.bind_host, self.bind_port
        self._running = True
        self._server = await start_server(
            self.bind_host, self.bind_port, self._on_inbound
        )
        socks = self._server.sockets or []
        if socks:
            addr = socks[0].getsockname()
            self.bind_port = int(addr[1])
        self._tasks.append(asyncio.create_task(self._heartbeat_loop()))
        self._tasks.append(asyncio.create_task(self._stale_scanner()))
        return self.bind_host, self.bind_port

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
        for conn in list(self._sessions.values()):
            await conn.close()
        self._sessions.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.store.close()

    async def connect_peer(self, host: str, port: int) -> dict[str, Any]:
        if len(self._sessions) >= self.max_connections:
            raise RuntimeError("connection limit reached")
        conn = await connect_tcp(host, port)
        peer = await self._handshake_as_initiator(conn)
        self._sessions[peer["node_id"]] = conn
        asyncio.create_task(self._session_loop(peer["node_id"], conn))
        return peer

    async def _on_inbound(self, conn: FramedConnection) -> None:
        if len(self._sessions) >= self.max_connections:
            await conn.send({"type": MsgType.ERROR.value, "error": "connection limit"})
            return
        try:
            peer = await self._handshake_as_responder(conn)
            self._sessions[peer["node_id"]] = conn
            await self._session_loop(peer["node_id"], conn)
        except (ProtocolError, ValueError, asyncio.CancelledError):
            return

    async def _handshake_as_initiator(self, conn: FramedConnection) -> dict[str, Any]:
        await conn.send(make_hello(self.identity, self.capabilities))
        challenge = await conn.recv()
        if challenge.get("type") != MsgType.CHALLENGE.value:
            raise ProtocolError("expected challenge")
        peer_nonce = challenge["nonce"]
        if self.store.seen_nonce(peer_nonce):
            raise ProtocolError("nonce replay")
        self.store.record_nonce(peer_nonce)
        local_nonce = secrets.token_urlsafe(32)
        await conn.send(make_response(self.identity, peer_nonce, local_nonce))
        msg = await conn.recv()
        if msg.get("type") == MsgType.AUTH_FAIL.value:
            raise ProtocolError(msg.get("error", "auth failed"))
        if msg.get("type") != MsgType.AUTH_OK.value:
            raise ProtocolError("expected auth_ok")
        peer_id = msg["node_id"]
        peer_key = msg["public_key"]
        caps = msg.get("capabilities", [])
        # Mutual auth: peer signed our local_nonce
        ok_msg = {
            "peer_nonce": msg.get("peer_nonce", local_nonce),
            "local_nonce": msg.get("local_nonce", ""),
            "node_id": peer_id,
            "signature": msg.get("signature", ""),
        }
        if not verify_response(ok_msg, local_nonce, peer_key):
            raise ProtocolError("peer auth_ok signature invalid")
        peer = self._persist_authenticated(peer_id, peer_key, caps, msg.get("identity"))
        self._emit("peer.authenticated", {"node_id": peer_id, "role": "initiator"})
        return peer

    async def _handshake_as_responder(self, conn: FramedConnection) -> dict[str, Any]:
        hello = await conn.recv()
        identity = validate_hello(hello)
        peer_id = identity["node_id"]
        peer_key = identity["public_key"]
        caps = hello.get("capabilities", [])

        challenge, nonce = make_challenge(self.identity)
        self.store.record_nonce(nonce)
        await conn.send(challenge)

        resp = await conn.recv()
        if resp.get("type") != MsgType.RESPONSE.value:
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "expected response"})
            raise ProtocolError("expected response")
        if self.store.seen_nonce(resp.get("local_nonce", "")):
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "nonce replay"})
            raise ProtocolError("nonce replay")
        self.store.record_nonce(resp["local_nonce"])
        if not verify_response(resp, nonce, peer_key):
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "bad signature"})
            raise ProtocolError("bad signature")

        our_resp = make_response(self.identity, resp["local_nonce"], nonce)
        await conn.send(
            {
                "type": MsgType.AUTH_OK.value,
                "node_id": self.identity.node_id,
                "public_key": self.identity.public_key_b64,
                "capabilities": self.capabilities,
                "identity": self.identity.signed_identity(),
                "peer_nonce": our_resp["peer_nonce"],
                "local_nonce": our_resp["local_nonce"],
                "signature": our_resp["signature"],
            }
        )
        peer = self._persist_authenticated(peer_id, peer_key, caps, identity)
        self._emit("peer.authenticated", {"node_id": peer_id, "role": "responder"})
        return peer

    def _persist_authenticated(
        self,
        node_id: str,
        public_key: str,
        capabilities: list[str],
        signed_identity: dict[str, Any] | None,
    ) -> dict[str, Any]:
        existing = self.store.get_peer(node_id)
        trust = TrustState.AUTHENTICATED.value
        if existing and existing["trust"] == TrustState.AUTHORIZED.value:
            trust = TrustState.AUTHORIZED.value
        if existing and existing["trust"] == TrustState.REVOKED.value:
            trust = TrustState.REVOKED.value
        peer = {
            "node_id": node_id,
            "public_key": public_key,
            "trust": trust,
            "reachability": Reachability.REACHABLE,
            "last_seen": time.time(),
            "capabilities": capabilities,
            "signed_identity": signed_identity,
            "observed_at": time.time(),
        }
        self.store.upsert_peer(peer)
        self.store.record_observation(node_id, "authenticated")
        return peer

    async def _session_loop(self, node_id: str, conn: FramedConnection) -> None:
        try:
            while self._running and not conn.closed:
                msg = await conn.recv()
                mtype = msg.get("type")
                if mtype == MsgType.HEARTBEAT.value:
                    self.store.set_reachability(
                        node_id,
                        Reachability.REACHABLE,
                        last_seen=time.time(),
                        seq=int(msg.get("seq", 0)),
                    )
                    await conn.send(
                        {
                            "type": MsgType.HEARTBEAT_ACK.value,
                            "seq": msg.get("seq", 0),
                            "ts": time.time(),
                        }
                    )
                elif mtype == MsgType.HEARTBEAT_ACK.value:
                    self.store.set_reachability(
                        node_id,
                        Reachability.REACHABLE,
                        last_seen=time.time(),
                        seq=int(msg.get("seq", 0)),
                    )
                elif mtype in (MsgType.GOODBYE.value, MsgType.ERROR.value):
                    break
        except ProtocolError:
            pass
        finally:
            self._sessions.pop(node_id, None)
            self.store.set_reachability(node_id, Reachability.UNREACHABLE)
            self.store.record_observation(node_id, "disconnected")
            self._emit("peer.disconnected", {"node_id": node_id})
            await conn.close()

    async def _heartbeat_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self.heartbeat_interval_s)
            self._hb_seq += 1
            seq = self._hb_seq
            for nid, conn in list(self._sessions.items()):
                try:
                    await conn.send(
                        {
                            "type": MsgType.HEARTBEAT.value,
                            "seq": seq,
                            "node_id": self.node_id,
                            "ts": time.time(),
                        }
                    )
                except Exception:
                    self.store.set_reachability(nid, Reachability.UNREACHABLE)

    async def _stale_scanner(self) -> None:
        while self._running:
            await asyncio.sleep(self.heartbeat_interval_s)
            now = time.time()
            for peer in self.store.list_peers():
                if peer["reachability"] == Reachability.REACHABLE:
                    age = now - peer["last_seen"]
                    if age > self.heartbeat_timeout_s:
                        self.store.set_reachability(peer["node_id"], Reachability.STALE)
                        self.store.record_observation(peer["node_id"], "stale")
                        self._emit("peer.stale", {"node_id": peer["node_id"], "age": age})

    def authorize_peer(self, node_id: str) -> None:
        peer = self.store.get_peer(node_id)
        if not peer:
            raise KeyError(f"unknown peer {node_id}")
        if peer["trust"] == TrustState.REVOKED.value:
            raise ValueError("cannot authorize revoked peer without re-enrollment")
        if peer["trust"] not in (
            TrustState.AUTHENTICATED.value,
            TrustState.AUTHORIZED.value,
        ):
            raise ValueError("peer must be authenticated before authorization")
        self.store.set_trust(node_id, TrustState.AUTHORIZED.value)
        self.store.record_observation(node_id, "authorized")
        self._emit("peer.authorized", {"node_id": node_id})

    def revoke_peer(self, node_id: str) -> None:
        if not self.store.get_peer(node_id):
            raise KeyError(f"unknown peer {node_id}")
        self.store.set_trust(node_id, TrustState.REVOKED.value)
        self.store.record_observation(node_id, "revoked")
        self._emit("peer.revoked", {"node_id": node_id})
        conn = self._sessions.pop(node_id, None)
        if conn:
            asyncio.create_task(conn.close())

    def list_peers(self) -> list[dict[str, Any]]:
        return self.store.list_peers()

    def topology_snapshot(self) -> dict[str, Any]:
        peers = self.store.list_peers()
        return {
            "local_node_id": self.node_id,
            "public_key": self.identity.public_key_b64,
            "bind": {"host": self.bind_host, "port": self.bind_port},
            "capabilities": self.capabilities,
            "peers": peers,
            "authenticated_peers": [
                p
                for p in peers
                if p["trust"]
                in (TrustState.AUTHENTICATED.value, TrustState.AUTHORIZED.value)
            ],
            "authorized_peers": [
                p for p in peers if p["trust"] == TrustState.AUTHORIZED.value
            ],
            "active_sessions": list(self._sessions.keys()),
            "routes": self.store.list_routes(),
            "gateways": self.store.list_gateways(),
            "transports": [{"type": "tcp", "bound": self._server is not None}],
        }

    def status(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "running": self._running,
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "peer_count": len(self.store.list_peers()),
            "active_sessions": len(self._sessions),
            "capabilities": self.capabilities,
        }
