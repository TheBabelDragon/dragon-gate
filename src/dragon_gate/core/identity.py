"""Ed25519 node identity and signed identity records."""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass
class NodeIdentity:
    """Stable node identity with Ed25519 key material."""

    node_id: str
    public_key_b64: str
    private_key_b64: str | None = None  # never exported in signed records
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_b64d(self.public_key_b64))

    @property
    def private_key(self) -> Ed25519PrivateKey | None:
        if not self.private_key_b64:
            return None
        return Ed25519PrivateKey.from_private_bytes(_b64d(self.private_key_b64))

    def sign(self, payload: bytes) -> str:
        if self.private_key is None:
            raise RuntimeError("Cannot sign without private key")
        return _b64(self.private_key.sign(payload))

    def verify(self, payload: bytes, signature_b64: str) -> bool:
        try:
            self.public_key.verify(_b64d(signature_b64), payload)
            return True
        except Exception:
            return False

    def identity_record(self) -> dict[str, Any]:
        """Public, signable identity record (no private key)."""
        return {
            "node_id": self.node_id,
            "public_key": self.public_key_b64,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    def signed_identity(self) -> dict[str, Any]:
        record = self.identity_record()
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        return {
            **record,
            "signature": self.sign(canonical),
            "signature_alg": "ed25519",
        }

    def to_dict(self, include_private: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if not include_private:
            d.pop("private_key_b64", None)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NodeIdentity:
        return cls(
            node_id=data["node_id"],
            public_key_b64=data["public_key_b64"],
            private_key_b64=data.get("private_key_b64"),
            created_at=data.get("created_at", time.time()),
            metadata=data.get("metadata", {}),
        )


def generate_identity(metadata: dict[str, Any] | None = None) -> NodeIdentity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    node_id = f"dg-{uuid.uuid4().hex[:16]}"
    return NodeIdentity(
        node_id=node_id,
        public_key_b64=_b64(
            public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
        private_key_b64=_b64(
            private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ),
        metadata=metadata or {},
    )


def default_identity_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "dragon-gate" / "identity.json"


def load_or_create_identity(path: Path | None = None) -> NodeIdentity:
    path = path or default_identity_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        data = json.loads(path.read_text())
        return NodeIdentity.from_dict(data)
    ident = generate_identity()
    path.write_text(json.dumps(ident.to_dict(include_private=True), indent=2))
    path.chmod(0o600)
    return ident


def verify_signed_identity(record: dict[str, Any]) -> bool:
    """Verify a signed identity record from a peer."""
    sig = record.get("signature")
    if not sig:
        return False
    public_b64 = record.get("public_key")
    if not public_b64:
        return False
    body = {k: v for k, v in record.items() if k not in ("signature", "signature_alg")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    try:
        key = Ed25519PublicKey.from_public_bytes(_b64d(public_b64))
        key.verify(_b64d(sig), canonical)
        return True
    except Exception:
        return False
