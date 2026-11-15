"""Canonical evidence event schema."""

from __future__ import annotations

import time
import uuid
from typing import Any

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0.0"


class EvidenceEvent(BaseModel):
    schema_version: str = SCHEMA_VERSION
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    node_id: str
    sequence: int = 0
    source_timestamp: float = Field(default_factory=time.time)
    ingest_timestamp: float = Field(default_factory=time.time)
    clock_source: str = "system"
    target_identity: str | None = None
    observation: dict[str, Any] = Field(default_factory=dict)
    tool_identity: str = "dragon-gate/0.1.0"
    provenance: dict[str, Any] = Field(default_factory=dict)
    content_hash: str | None = None

    def with_hash(self) -> EvidenceEvent:
        from .store import hash_content, canonical_json

        body = self.model_dump(exclude={"content_hash"})
        h = hash_content(canonical_json(body))
        return self.model_copy(update={"content_hash": h})
