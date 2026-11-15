"""Multi-node peer runtime — auth, persistence, heartbeat, adversarial."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from dragon_gate.core.identity import generate_identity
from dragon_gate.network.peers import TrustState
from dragon_gate.runtime.node import NodeRuntime, Reachability
from dragon_gate.runtime.protocol import (
    encode_message,
    make_hello,
    make_response,
    validate_hello,
    verify_response,
)
from dragon_gate.runtime.session_crypto import SecureSession, derive_session_keys
from dragon_gate.runtime.store import PeerStore
from dragon_gate.runtime.transport import ProtocolError


@pytest.fixture
def tmp_runtime(tmp_path: Path):
    async def _make(name: str, port: int = 0):
        rt = NodeRuntime(
            data_dir=tmp_path / name,
            bind_host="127.0.0.1",
            bind_port=port,
            heartbeat_interval_s=0.2,
            heartbeat_timeout_s=1.0,
        )
        host, p = await rt.start()
        return rt, host, p

    return _make


@pytest.mark.asyncio
async def test_two_nodes_mutual_auth(tmp_runtime):
    a, _, port_a = await tmp_runtime("a")
    b, _, _ = await tmp_runtime("b")
    try:
        peer = await b.connect_peer("127.0.0.1", port_a)
        assert peer["trust"] == TrustState.AUTHENTICATED.value
        await asyncio.sleep(0.3)
        peers_a = a.list_peers()
        peers_b = b.list_peers()
        assert any(p["node_id"] == b.node_id for p in peers_a)
        assert any(p["node_id"] == a.node_id for p in peers_b)
    finally:
        await a.stop()
        await b.stop()


@pytest.mark.asyncio
async def test_authorize_and_revoke(tmp_runtime):
    a, _, port_a = await tmp_runtime("a2")
    b, _, _ = await tmp_runtime("b2")
    try:
        await b.connect_peer("127.0.0.1", port_a)
        await asyncio.sleep(0.2)
        a.authorize_peer(b.node_id)
        assert a.store.get_peer(b.node_id)["trust"] == TrustState.AUTHORIZED.value
        a.revoke_peer(b.node_id)
        assert a.store.get_peer(b.node_id)["trust"] == TrustState.REVOKED.value
        assert b.node_id not in a._sessions
    finally:
        await a.stop()
        await b.stop()


@pytest.mark.asyncio
async def test_revoked_cannot_reconnect(tmp_runtime):
    a, _, port_a = await tmp_runtime("rev_a")
    b, _, _ = await tmp_runtime("rev_b")
    try:
        await b.connect_peer("127.0.0.1", port_a)
        await asyncio.sleep(0.15)
        a.revoke_peer(b.node_id)
        await asyncio.sleep(0.1)
        with pytest.raises((ProtocolError, Exception)):
            await b.connect_peer("127.0.0.1", port_a)
        assert a.store.get_peer(b.node_id)["trust"] == TrustState.REVOKED.value
    finally:
        await a.stop()
        await b.stop()


@pytest.mark.asyncio
async def test_revocation_persists_across_restart(tmp_path):
    d = tmp_path / "rev_persist"
    rt1 = NodeRuntime(data_dir=d, bind_host="127.0.0.1", bind_port=0)
    await rt1.start()
    rt1.store.upsert_peer(
        {
            "node_id": "dg-bad",
            "public_key": "pk",
            "trust": TrustState.REVOKED.value,
        }
    )
    await rt1.stop()
    rt2 = NodeRuntime(data_dir=d, bind_host="127.0.0.1", bind_port=0)
    await rt2.start()
    try:
        assert rt2.store.get_peer("dg-bad")["trust"] == TrustState.REVOKED.value
        assert rt2._is_revoked("dg-bad")
    finally:
        await rt2.stop()


@pytest.mark.asyncio
async def test_cannot_authorize_unauthenticated(tmp_path):
    rt = NodeRuntime(data_dir=tmp_path / "solo", bind_host="127.0.0.1", bind_port=0)
    await rt.start()
    try:
        rt.store.upsert_peer(
            {
                "node_id": "dg-fake",
                "public_key": "x",
                "trust": TrustState.DISCOVERED.value,
            }
        )
        with pytest.raises(ValueError, match="authenticated"):
            rt.authorize_peer("dg-fake")
    finally:
        await rt.stop()


@pytest.mark.asyncio
async def test_persistence_across_restart(tmp_path):
    d = tmp_path / "persist"
    rt1 = NodeRuntime(data_dir=d, bind_host="127.0.0.1", bind_port=0)
    await rt1.start()
    node_id = rt1.node_id
    rt1.store.upsert_peer(
        {
            "node_id": "dg-saved",
            "public_key": "pk",
            "trust": TrustState.AUTHENTICATED.value,
            "reachability": Reachability.REACHABLE,
        }
    )
    await rt1.stop()

    rt2 = NodeRuntime(data_dir=d, bind_host="127.0.0.1", bind_port=0)
    await rt2.start()
    try:
        assert rt2.node_id == node_id
        p = rt2.store.get_peer("dg-saved")
        assert p is not None
        assert p["trust"] == TrustState.AUTHENTICATED.value
    finally:
        await rt2.stop()


def test_invalid_signature_hello():
    ident = generate_identity()
    hello = make_hello(ident, ["gate-core"])
    hello["identity"]["signature"] = "AAAA"
    with pytest.raises(ValueError):
        validate_hello(hello)


def test_response_nonce_binding():
    a = generate_identity()
    resp = make_response(a, "nonce-from-b", "nonce-from-a")
    assert verify_response(resp, "nonce-from-b", a.public_key_b64)
    assert not verify_response(resp, "wrong", a.public_key_b64)


def test_oversized_message_rejected():
    huge = {"type": "x", "data": "Z" * (70 * 1024)}
    with pytest.raises(ValueError, match="exceeds"):
        encode_message(huge)


def test_store_nonce_replay(tmp_path):
    store = PeerStore(tmp_path / "n.db")
    assert store.claim_nonce("abc")
    assert not store.claim_nonce("abc")
    assert store.seen_nonce("abc")
    store.close()


def test_session_mac_and_replay():
    k1, k2 = derive_session_keys(
        initiator_nonce="n1",
        responder_nonce="n2",
        initiator_pubkey="pk1",
        responder_pubkey="pk2",
        initiator_node="a",
        responder_node="b",
    )
    send = SecureSession("b", send_key=k1, recv_key=k2)
    recv = SecureSession("a", send_key=k2, recv_key=k1)
    frame = send.seal("heartbeat", {"node_id": "a"})
    opened = recv.open(frame)
    assert opened["type"] == "heartbeat"
    with pytest.raises(ValueError, match="replay|order"):
        recv.open(frame)
    tampered = dict(frame)
    tampered["node_id"] = "evil"
    with pytest.raises(ValueError, match="mac"):
        # new session state already advanced; use fresh recv
        recv2 = SecureSession("a", send_key=k2, recv_key=k1)
        recv2.open(tampered)


@pytest.mark.asyncio
async def test_topology_snapshot(tmp_runtime):
    a, _, port_a = await tmp_runtime("topo_a")
    b, _, _ = await tmp_runtime("topo_b")
    try:
        await b.connect_peer("127.0.0.1", port_a)
        await asyncio.sleep(0.2)
        snap = a.topology_snapshot()
        assert snap["local_node_id"] == a.node_id
        assert isinstance(snap["peers"], list)
        assert snap["transports"]
    finally:
        await a.stop()
        await b.stop()


@pytest.mark.asyncio
async def test_no_internet_required(tmp_runtime):
    a, _, port_a = await tmp_runtime("offline_a")
    b, _, _ = await tmp_runtime("offline_b")
    try:
        peer = await b.connect_peer("127.0.0.1", port_a)
        assert peer["node_id"] == a.node_id
    finally:
        await a.stop()
        await b.stop()
