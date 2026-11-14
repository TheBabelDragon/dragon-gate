"""Evidence store, canonical serialization, hashing, verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .schema import EvidenceEvent


def canonical_json(obj: Any) -> bytes:
    """Stable, deterministic JSON serialization."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def hash_content(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class EvidenceStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._events: list[EvidenceEvent] = []
        self._seq = 0

    def append(self, event: EvidenceEvent) -> EvidenceEvent:
        self._seq += 1
        event = event.model_copy(update={"sequence": self._seq})
        event = event.with_hash()
        self._events.append(event)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
        return event

    def events(self) -> list[EvidenceEvent]:
        return list(self._events)

    def export_ndjson(self) -> str:
        return "\n".join(e.model_dump_json() for e in self._events) + ("\n" if self._events else "")

    @staticmethod
    def verify_event(event: EvidenceEvent | dict[str, Any]) -> bool:
        if isinstance(event, EvidenceEvent):
            data = event.model_dump()
        else:
            data = dict(event)
        expected = data.pop("content_hash", None)
        if not expected:
            return False
        actual = hash_content(canonical_json(data))
        return actual == expected

    @staticmethod
    def load_ndjson(path: Path) -> list[EvidenceEvent]:
        events: list[EvidenceEvent] = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(EvidenceEvent.model_validate_json(line))
        return events

    @staticmethod
    def verify_file(path: Path) -> tuple[int, int]:
        """Return (ok_count, fail_count)."""
        ok = fail = 0
        for ev in EvidenceStore.load_ndjson(path):
            if EvidenceStore.verify_event(ev):
                ok += 1
            else:
                fail += 1
        return ok, fail
