"""Post-handshake session integrity using HKDF + HMAC-SHA256.

Construction (reviewed primitives from cryptography):
  - Session master from HKDF-SHA256 over sorted nonces + both public keys
  - Directional keys: send_key / recv_key (key separation)
  - Each application message carries seq + HMAC over (seq || type || body)
  - Strict monotonically increasing sequence per direction
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dragon_gate.core.identity import _b64, _b64d

SESSION_TTL_S = 3600.0


def derive_session_keys(
    *,
    initiator_nonce: str,
    responder_nonce: str,
    initiator_pubkey: str,
    responder_pubkey: str,
    initiator_node: str,
    responder_node: str,
) -> tuple[bytes, bytes]:
    """Return (initiator_to_responder_key, responder_to_initiator_key)."""
    # Deterministic IKM ordering
    ikm = "|".join(
        sorted([initiator_nonce, responder_nonce, initiator_pubkey, responder_pubkey])
    ).encode()
    info = f"dragon-gate-v1|{initiator_node}|{responder_node}".encode()
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"dragon-gate-session-v1",
        info=info,
    ).derive(ikm)
    return material[:32], material[32:]


def canonical_transcript(parts: dict[str, Any]) -> bytes:
    return json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()


def sign_transcript(identity, parts: dict[str, Any]) -> str:
    return identity.sign(canonical_transcript(parts))


def verify_transcript_sig(public_key_b64: str, parts: dict[str, Any], signature_b64: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64))
        key.verify(_b64d(signature_b64), canonical_transcript(parts))
        return True
    except Exception:
        return False


@dataclass
class SecureSession:
    peer_node_id: str
    send_key: bytes
    recv_key: bytes
    send_seq: int = 0
    recv_seq: int = 0
    created_mono: float = field(default_factory=time.monotonic)
    ttl_s: float = SESSION_TTL_S
    outstanding_hb: set[int] = field(default_factory=set)

    def expired(self) -> bool:
        return (time.monotonic() - self.created_mono) > self.ttl_s

    def seal(self, msg_type: str, body: dict[str, Any]) -> dict[str, Any]:
        if self.expired():
            raise ValueError("session expired")
        self.send_seq += 1
        seq = self.send_seq
        payload = {"type": msg_type, "seq": seq, **body}
        mac = self._mac(self.send_key, seq, msg_type, payload)
        payload["mac"] = mac
        return payload

    def open(self, frame: dict[str, Any]) -> dict[str, Any]:
        if self.expired():
            raise ValueError("session expired")
        mac = frame.get("mac")
        if not mac:
            raise ValueError("missing mac")
        seq = int(frame.get("seq", -1))
        if seq <= self.recv_seq:
            raise ValueError("replay or out-of-order sequence")
        msg_type = frame.get("type", "")
        check = {k: v for k, v in frame.items() if k != "mac"}
        expected = self._mac(self.recv_key, seq, msg_type, check)
        if not hmac.compare_digest(expected, mac):
            raise ValueError("mac verification failed")
        self.recv_seq = seq
        return frame

    @staticmethod
    def _mac(key: bytes, seq: int, msg_type: str, payload: dict[str, Any]) -> str:
        # Exclude mac field if present
        body = {k: v for k, v in payload.items() if k != "mac"}
        body["seq"] = seq
        body["type"] = msg_type
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return _b64(hmac.new(key, data, hashlib.sha256).digest())
