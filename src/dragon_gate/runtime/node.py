"""NodeRuntime — hardened multi-node control plane (v0.3.1)."""

from __future__ import annotations

import asyncio
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from dragon_gate.core.identity import NodeIdentity, load_or_create_identity, verify_signed_identity
from dragon_gate.network.peers import TrustState
from dragon_gate.runtime.protocol import (
    PROTOCOL_VERSION,
    MsgType,
    make_challenge,
    make_hello,
    validate_hello,
)
from dragon_gate.runtime.session_crypto import (
    SecureSession,
    derive_session_keys,
    sign_transcript,
    verify_transcript_sig,
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
        self._secure: dict[str, SecureSession] = {}
        self._last_hb_mono: dict[str, float] = {}
        self._tasks: list[asyncio.Task] = []
        self._running = False

    @property
    def node_id(self) -> str:
        return self.identity.node_id

    def _emit(self, event_type: str, observation: dict[str, Any]) -> None:
        if self._evidence:
            self._evidence(event_type, observation)

    def _is_revoked(self, node_id: str) -> bool:
        p = self.store.get_peer(node_id)
        return bool(p and p["trust"] == TrustState.REVOKED.value)

    async def start(self) -> tuple[str, int]:
        if self._running:
            return self.bind_host, self.bind_port
        self._running = True
        self._server = await start_server(
            self.bind_host, self.bind_port, self._on_inbound
        )
        socks = self._server.sockets or []
        if socks:
            self.bind_port = int(socks[0].getsockname()[1])
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
        self._secure.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.store.close()

    async def connect_peer(self, host: str, port: int) -> dict[str, Any]:
        if len(self._sessions) >= self.max_connections:
            raise RuntimeError("connection limit reached")
        conn = await connect_tcp(host, port)
        peer, sec = await self._handshake_as_initiator(conn)
        if self._is_revoked(peer["node_id"]):
            await conn.close()
            raise ProtocolError("peer is revoked")
        self._sessions[peer["node_id"]] = conn
        self._secure[peer["node_id"]] = sec
        self._last_hb_mono[peer["node_id"]] = time.monotonic()
        asyncio.create_task(self._session_loop(peer["node_id"], conn, sec))
        return peer

    async def _on_inbound(self, conn: FramedConnection) -> None:
        if len(self._sessions) >= self.max_connections:
            await conn.send({"type": MsgType.ERROR.value, "error": "connection limit"})
            return
        try:
            peer, sec = await self._handshake_as_responder(conn)
            if self._is_revoked(peer["node_id"]):
                await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "revoked"})
                return
            self._sessions[peer["node_id"]] = conn
            self._secure[peer["node_id"]] = sec
            self._last_hb_mono[peer["node_id"]] = time.monotonic()
            await self._session_loop(peer["node_id"], conn, sec)
        except (ProtocolError, ValueError, asyncio.CancelledError):
            return

    async def _handshake_as_initiator(
        self, conn: FramedConnection
    ) -> tuple[dict[str, Any], SecureSession]:
        await conn.send(make_hello(self.identity, self.capabilities))
        challenge = await conn.recv()
        if challenge.get("type") != MsgType.CHALLENGE.value:
            raise ProtocolError("expected challenge")
        peer_nonce = challenge.get("nonce")
        if not peer_nonce or not isinstance(peer_nonce, str):
            raise ProtocolError("malformed challenge")
        if not self.store.claim_nonce(peer_nonce, session_hint="inbound-challenge"):
            raise ProtocolError("nonce replay or expired")

        local_nonce = secrets.token_urlsafe(32)
        self.store.claim_nonce(local_nonce, session_hint="local")

        transcript_partial = {
            "protocol_version": PROTOCOL_VERSION,
            "initiator_node": self.node_id,
            "initiator_pubkey": self.identity.public_key_b64,
            "responder_nonce": peer_nonce,
            "initiator_nonce": local_nonce,
            "initiator_capabilities": sorted(self.capabilities),
        }
        sig = sign_transcript(self.identity, transcript_partial)
        await conn.send(
            {
                "type": MsgType.RESPONSE.value,
                "node_id": self.node_id,
                "peer_nonce": peer_nonce,
                "local_nonce": local_nonce,
                "transcript": transcript_partial,
                "signature": sig,
                "ts": time.time(),
            }
        )

        msg = await conn.recv()
        if msg.get("type") == MsgType.AUTH_FAIL.value:
            raise ProtocolError(msg.get("error", "auth failed"))
        if msg.get("type") != MsgType.AUTH_OK.value:
            raise ProtocolError("expected auth_ok")

        identity = msg.get("identity") or {}
        if not verify_signed_identity(identity):
            raise ProtocolError("AUTH_OK identity signature invalid")
        peer_id = identity["node_id"]
        peer_key = identity["public_key"]
        if msg.get("node_id") != peer_id or msg.get("public_key") != peer_key:
            raise ProtocolError("identity substitution")
        if self._is_revoked(peer_id):
            raise ProtocolError("peer is revoked")

        caps = sorted(msg.get("capabilities") or [])
        full_transcript = {
            **transcript_partial,
            "responder_node": peer_id,
            "responder_pubkey": peer_key,
            "responder_capabilities": caps,
        }
        if not verify_transcript_sig(peer_key, full_transcript, msg.get("signature", "")):
            raise ProtocolError("AUTH_OK transcript signature invalid")

        i_to_r, r_to_i = derive_session_keys(
            initiator_nonce=local_nonce,
            responder_nonce=peer_nonce,
            initiator_pubkey=self.identity.public_key_b64,
            responder_pubkey=peer_key,
            initiator_node=self.node_id,
            responder_node=peer_id,
        )
        sec = SecureSession(peer_node_id=peer_id, send_key=i_to_r, recv_key=r_to_i)
        peer = self._persist_authenticated(peer_id, peer_key, caps, identity)
        self._emit("peer.authenticated", {"node_id": peer_id, "role": "initiator"})
        return peer, sec

    async def _handshake_as_responder(
        self, conn: FramedConnection
    ) -> tuple[dict[str, Any], SecureSession]:
        hello = await conn.recv()
        identity = validate_hello(hello)
        peer_id = identity["node_id"]
        peer_key = identity["public_key"]
        if self._is_revoked(peer_id):
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "revoked"})
            raise ProtocolError("revoked")
        peer_caps = sorted(hello.get("capabilities") or [])

        challenge, nonce = make_challenge(self.identity)
        self.store.claim_nonce(nonce, session_hint=f"challenge-{peer_id}")
        await conn.send(challenge)

        resp = await conn.recv()
        if resp.get("type") != MsgType.RESPONSE.value:
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "expected response"})
            raise ProtocolError("expected response")
        local_nonce = resp.get("local_nonce")
        if not local_nonce or not self.store.claim_nonce(
            local_nonce, session_hint="peer-local"
        ):
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "nonce replay"})
            raise ProtocolError("nonce replay")
        if resp.get("peer_nonce") != nonce:
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "nonce bind"})
            raise ProtocolError("nonce bind")
        if resp.get("node_id") != peer_id:
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "identity mismatch"})
            raise ProtocolError("identity mismatch")

        partial = resp.get("transcript") or {}
        if not verify_transcript_sig(peer_key, partial, resp.get("signature", "")):
            await conn.send({"type": MsgType.AUTH_FAIL.value, "error": "bad transcript"})
            raise ProtocolError("bad transcript")

        full_transcript = {
            "protocol_version": PROTOCOL_VERSION,
            "initiator_node": peer_id,
            "initiator_pubkey": peer_key,
            "responder_nonce": nonce,
            "initiator_nonce": local_nonce,
            "initiator_capabilities": peer_caps,
            "responder_node": self.node_id,
            "responder_pubkey": self.identity.public_key_b64,
            "responder_capabilities": sorted(self.capabilities),
        }
        for k in (
            "protocol_version",
            "initiator_node",
            "initiator_pubkey",
            "responder_nonce",
            "initiator_nonce",
        ):
            if partial.get(k) != full_transcript.get(k):
                await conn.send(
                    {"type": MsgType.AUTH_FAIL.value, "error": "transcript mismatch"}
                )
                raise ProtocolError("transcript mismatch")

        sig = sign_transcript(self.identity, full_transcript)
        await conn.send(
            {
                "type": MsgType.AUTH_OK.value,
                "node_id": self.identity.node_id,
                "public_key": self.identity.public_key_b64,
                "capabilities": self.capabilities,
                "identity": self.identity.signed_identity(),
                "transcript": full_transcript,
                "signature": sig,
            }
        )

        i_to_r, r_to_i = derive_session_keys(
            initiator_nonce=local_nonce,
            responder_nonce=nonce,
            initiator_pubkey=peer_key,
            responder_pubkey=self.identity.public_key_b64,
            initiator_node=peer_id,
            responder_node=self.node_id,
        )
        sec = SecureSession(peer_node_id=peer_id, send_key=r_to_i, recv_key=i_to_r)
        peer = self._persist_authenticated(peer_id, peer_key, peer_caps, identity)
        self._emit("peer.authenticated", {"node_id": peer_id, "role": "responder"})
        return peer, sec

    def _persist_authenticated(
        self,
        node_id: str,
        public_key: str,
        capabilities: list[str],
        signed_identity: dict[str, Any] | None,
    ) -> dict[str, Any]:
        existing = self.store.get_peer(node_id)
        if existing and existing["trust"] == TrustState.REVOKED.value:
            return {
                "node_id": node_id,
                "public_key": public_key,
                "trust": TrustState.REVOKED.value,
                "reachability": Reachability.UNREACHABLE,
                "capabilities": capabilities,
                "signed_identity": signed_identity,
            }
        trust = TrustState.AUTHENTICATED.value
        if existing and existing["trust"] == TrustState.AUTHORIZED.value:
            trust = TrustState.AUTHORIZED.value
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

    async def _session_loop(
        self, node_id: str, conn: FramedConnection, sec: SecureSession
    ) -> None:
        try:
            while self._running and not conn.closed:
                if self._is_revoked(node_id):
                    break
                if sec.expired():
                    break
                raw = await conn.recv()
                try:
                    msg = sec.open(raw)
                except ValueError:
                    break
                mtype = msg.get("type")
                if mtype == MsgType.HEARTBEAT.value:
                    seq = int(msg.get("seq", 0))
                    self._last_hb_mono[node_id] = time.monotonic()
                    self.store.set_reachability(
                        node_id,
                        Reachability.REACHABLE,
                        last_seen=time.time(),
                        seq=seq,
                    )
                    ack = sec.seal(MsgType.HEARTBEAT_ACK.value, {"ack_seq": seq})
                    await conn.send(ack)
                elif mtype == MsgType.HEARTBEAT_ACK.value:
                    ack_seq = int(msg.get("ack_seq", -1))
                    if ack_seq not in sec.outstanding_hb:
                        continue
                    sec.outstanding_hb.discard(ack_seq)
                    self._last_hb_mono[node_id] = time.monotonic()
                    self.store.set_reachability(
                        node_id,
                        Reachability.REACHABLE,
                        last_seen=time.time(),
                        seq=ack_seq,
                    )
                elif mtype in (MsgType.GOODBYE.value, MsgType.ERROR.value):
                    break
        except ProtocolError:
            pass
        finally:
            self._sessions.pop(node_id, None)
            self._secure.pop(node_id, None)
            self._last_hb_mono.pop(node_id, None)
            if not self._is_revoked(node_id):
                self.store.set_reachability(node_id, Reachability.UNREACHABLE)
            self.store.record_observation(node_id, "disconnected")
            self._emit("peer.disconnected", {"node_id": node_id})
            await conn.close()

    async def _heartbeat_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self.heartbeat_interval_s)
            for nid, conn in list(self._sessions.items()):
                sec = self._secure.get(nid)
                if not sec or sec.expired():
                    await conn.close()
                    continue
                try:
                    frame = sec.seal(MsgType.HEARTBEAT.value, {"node_id": self.node_id})
                    sec.outstanding_hb.add(frame["seq"])
                    if len(sec.outstanding_hb) > 32:
                        sec.outstanding_hb = set(sorted(sec.outstanding_hb)[-16:])
                    await conn.send(frame)
                except Exception:
                    self.store.set_reachability(nid, Reachability.UNREACHABLE)

    async def _stale_scanner(self) -> None:
        while self._running:
            await asyncio.sleep(self.heartbeat_interval_s)
            now_mono = time.monotonic()
            for peer in self.store.list_peers():
                nid = peer["node_id"]
                if peer["reachability"] != Reachability.REACHABLE:
                    continue
                if nid not in self._sessions:
                    self.store.set_reachability(nid, Reachability.UNREACHABLE)
                    continue
                last = self._last_hb_mono.get(nid, 0.0)
                if (now_mono - last) > self.heartbeat_timeout_s:
                    self.store.set_reachability(nid, Reachability.STALE)
                    self.store.record_observation(nid, "stale")
                    self._emit("peer.stale", {"node_id": nid})

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
        self._secure.pop(node_id, None)
        self._last_hb_mono.pop(node_id, None)
        if conn:
            asyncio.create_task(conn.close())

    def reenroll_clear_revocation(self, node_id: str) -> None:
        peer = self.store.get_peer(node_id)
        if not peer:
            raise KeyError(f"unknown peer {node_id}")
        if peer["trust"] != TrustState.REVOKED.value:
            raise ValueError("peer is not revoked")
        self.store.set_trust(node_id, TrustState.DISCOVERED.value)
        self.store.record_observation(node_id, "reenroll_cleared")

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
