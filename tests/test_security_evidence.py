"""Security evidence emission, redaction, hash verification."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from dragon_gate.evidence.store import EvidenceStore
from dragon_gate.security.pinned_transport import PinnedResponse
from dragon_gate.web.redirect import RedirectObservatory, RedirectPolicy


def test_inspect_emits_evidence(tmp_path: Path):
    store = EvidenceStore(path=tmp_path / "ev.ndjson")
    obs = RedirectObservatory(
        policy=RedirectPolicy.INSPECT_ONLY,
        evidence_store=store,
        node_id="dg-test",
    )
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()
        with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
            inst = Client.return_value
            inst.request.return_value = PinnedResponse(
                status_code=200,
                headers={},
                content=b"ok",
                url="https://example.com/",
                resolved_addresses=["93.184.216.34"],
                connected_address="93.184.216.34",
            )
            result = obs.inspect("https://example.com/")
    assert result.evidence_event_ids
    ok, fail = EvidenceStore.verify_file(tmp_path / "ev.ndjson")
    assert ok >= 1 and fail == 0
    events = EvidenceStore.load_ndjson(tmp_path / "ev.ndjson")
    types = {e.event_type for e in events}
    assert "web.redirect.inspect_started" in types


def test_blocked_emits_ssrf_evidence(tmp_path: Path):
    store = EvidenceStore(path=tmp_path / "ev.ndjson")
    obs = RedirectObservatory(evidence_store=store, node_id="dg-test")
    result = obs.inspect("http://127.0.0.1/")
    assert result.error
    events = EvidenceStore.load_ndjson(tmp_path / "ev.ndjson")
    assert any(e.event_type == "security.ssrf.blocked" for e in events)
    # no private keys or auth headers in observations
    for e in events:
        blob = str(e.observation)
        assert "private_key" not in blob
        assert "authorization" not in blob.lower()
