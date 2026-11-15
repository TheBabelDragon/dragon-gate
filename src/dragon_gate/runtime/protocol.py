"""Authenticated peer control protocol messages and handshake helpers."""

from __future__ import annotations

import json
import secrets
import time
from enum import Enum
from typing import Any

from dragon_gate.core.identity import NodeIdentity, verify_signed_identity, _b64, _b64d
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 64 * 1024


class MsgType(str, Enum):
    HELLO = "hello"
    CHALLENGE = "challenge"
    RESPONSE = "response"
    AUTH_OK = "auth_ok"
    AUTH_FAIL = "auth_fail"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    CAPABILITIES = "capabilities"
    ERROR = "error"
    GOODBYE = "goodbye"


def encode_message(msg: dict[str, Any]) -> bytes:
    raw = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError(f"message exceeds {MAX_MESSAGE_BYTES} bytes")
    # 4-byte big-endian length prefix
    return len(raw).to_bytes(4, "big") + raw


def decode_frame(frame: bytes) -> dict[str, Any]:
    if len(frame) > MAX_MESSAGE_BYTES:
        raise ValueError("frame too large")
    return json.loads(frame.decode("utf-8"))


def make_hello(identity: NodeIdentity, capabilities: list[str]) -> dict[str, Any]:
    signed = identity.signed_identity()
    return {
        "type": MsgType.HELLO.value,
        "protocol_version": PROTOCOL_VERSION,
        "identity": signed,
        "capabilities": capabilities,
        "ts": time.time(),
    }


def make_challenge(identity: NodeIdentity) -> tuple[dict[str, Any], str]:
    nonce = secrets.token_urlsafe(32)
    body = {
        "type": MsgType.CHALLENGE.value,
        "from_node": identity.node_id,
        "nonce": nonce,
        "ts": time.time(),
    }
    return body, nonce


def make_response(
    identity: NodeIdentity, peer_nonce: str, local_nonce: str
) -> dict[str, Any]:
    payload = json.dumps(
        {"peer_nonce": peer_nonce, "local_nonce": local_nonce, "node_id": identity.node_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    sig = identity.sign(payload)
    return {
        "type": MsgType.RESPONSE.value,
        "node_id": identity.node_id,
        "peer_nonce": peer_nonce,
        "local_nonce": local_nonce,
        "signature": sig,
        "ts": time.time(),
    }


def verify_response(
    msg: dict[str, Any],
    expected_peer_nonce: str,
    peer_public_key_b64: str,
) -> bool:
    if msg.get("peer_nonce") != expected_peer_nonce:
        return False
    payload = json.dumps(
        {
            "peer_nonce": msg["peer_nonce"],
            "local_nonce": msg["local_nonce"],
            "node_id": msg["node_id"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    try:
        key = Ed25519PublicKey.from_public_bytes(_b64d(peer_public_key_b64))
        key.verify(_b64d(msg["signature"]), payload)
        return True
    except Exception:
        return False


def validate_hello(msg: dict[str, Any]) -> dict[str, Any]:
    if msg.get("type") != MsgType.HELLO.value:
        raise ValueError("expected hello")
    ver = msg.get("protocol_version")
    if ver != PROTOCOL_VERSION:
        raise ValueError(f"unsupported protocol version: {ver}")
    identity = msg.get("identity") or {}
    if not verify_signed_identity(identity):
        raise ValueError("invalid identity signature")
    return identity
