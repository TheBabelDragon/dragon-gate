"""Evidence schema, hashing, verification, replay."""

from pathlib import Path

from dragon_gate.evidence.schema import EvidenceEvent
from dragon_gate.evidence.store import EvidenceStore, canonical_json, hash_content


def test_hash_stable():
    a = {"x": 1, "y": [2, 3]}
    b = {"y": [2, 3], "x": 1}
    assert hash_content(canonical_json(a)) == hash_content(canonical_json(b))


def test_event_with_hash():
    ev = EvidenceEvent(event_type="test.observation", node_id="dg-test")
    hashed = ev.with_hash()
    assert hashed.content_hash and hashed.content_hash.startswith("sha256:")
    assert EvidenceStore.verify_event(hashed)


def test_ndjson_roundtrip(tmp_path: Path):
    store = EvidenceStore(path=tmp_path / "events.ndjson")
    for i in range(3):
        store.append(
            EvidenceEvent(event_type="test", node_id="dg-test", observation={"i": i})
        )
    ok, fail = EvidenceStore.verify_file(tmp_path / "events.ndjson")
    assert ok == 3 and fail == 0
    events = EvidenceStore.load_ndjson(tmp_path / "events.ndjson")
    assert len(events) == 3
    assert events[0].sequence == 1
