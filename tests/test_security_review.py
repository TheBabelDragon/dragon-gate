"""Security review regression suite — pinning, redirects, credentials, redaction."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dragon_gate.evidence.store import EvidenceStore
from dragon_gate.security.pinned_transport import (
    PinnedHTTPClient,
    PinnedResponse,
    _safe_request_headers,
    make_test_ssrf,
)
from dragon_gate.security.ssrf import SSRFError, SSRFProtection, validate_resolved_addresses
from dragon_gate.web.redirect import RedirectObservatory, RedirectPolicy, _redact_url


def test_forbidden_headers_stripped_from_requests():
    h = _safe_request_headers(
        "example.com",
        {
            "Authorization": "Bearer secret",
            "Cookie": "sid=abc",
            "X-Custom": "ok",
        },
    )
    assert "Authorization" not in h
    assert "Cookie" not in h
    assert h["Host"] == "example.com"
    assert h["X-Custom"] == "ok"


def test_pinned_response_to_dict_redacts_query():
    r = PinnedResponse(
        status_code=200,
        headers={"Authorization": "Bearer x", "Content-Type": "text/plain"},
        content=b"hi",
        url="https://api.example.com/v1?token=secret",
        connected_address="1.1.1.1",
    )
    d = r.to_dict()
    assert "token" not in d["url"]
    assert "secret" not in d["url"]
    assert "Authorization" not in d["headers"]


def test_https_sni_uses_hostname_not_ip():
    ssrf = make_test_ssrf({"ok.test": ["1.1.1.1"]})
    client = PinnedHTTPClient(ssrf=ssrf, timeout_s=2.0)
    wrap_calls: list[str] = []

    def tracking_wrap(self, sock, *args, server_hostname=None, **kwargs):
        wrap_calls.append(server_hostname or "")
        raise OSError("stop after SNI observation")

    with patch(
        "dragon_gate.security.pinned_transport.socket.create_connection",
        side_effect=lambda *a, **k: MagicMock(),
    ):
        with patch("ssl.SSLContext.wrap_socket", tracking_wrap):
            with pytest.raises(ConnectionError):
                client.request("GET", "https://ok.test/")

    assert wrap_calls, "TLS wrap_socket was not called"
    assert wrap_calls[0] == "ok.test"
    assert wrap_calls[0] != "1.1.1.1"


def test_ipv6_loopback_and_ula_rejected():
    with pytest.raises(SSRFError):
        validate_resolved_addresses("x", ["::1"])
    with pytest.raises(SSRFError):
        validate_resolved_addresses("x", ["fe80::1"])
    with pytest.raises(SSRFError):
        validate_resolved_addresses("x", ["fd00::1"])


def test_multi_hop_redirect_revalidates_each_host():
    def resolver(hostname: str) -> list[str]:
        if hostname == "public.test":
            return ["1.1.1.1"]
        if hostname == "evil.internal":
            return ["10.0.0.9"]
        raise SSRFError("dns", reason="dns_failure")

    ssrf = SSRFProtection(resolver=resolver)
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE, ssrf=ssrf)

    with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
        inst = Client.return_value

        def req(method, url):
            if "public.test" in url:
                return PinnedResponse(
                    302,
                    {"location": "https://evil.internal/"},
                    b"",
                    url,
                    ["1.1.1.1"],
                    "1.1.1.1",
                )
            raise AssertionError("must not connect to evil.internal")

        inst.request.side_effect = req
        result = obs.inspect("https://public.test/")

    assert result.error and "blocked" in result.error.lower()


def test_dns_answer_change_between_hops_uses_fresh_resolution():
    answers = {
        "a.test": ["1.1.1.1"],
        "b.test": ["8.8.8.8"],
    }
    ssrf = make_test_ssrf(answers)
    r1 = ssrf.resolve("a.test")
    r2 = ssrf.resolve("b.test")
    assert r1.addresses == ["1.1.1.1"]
    assert r2.addresses == ["8.8.8.8"]
    answers["a.test"] = ["127.0.0.1"]
    with pytest.raises(SSRFError):
        ssrf.resolve("a.test")


def test_evidence_never_contains_query_tokens(tmp_path: Path):
    store = EvidenceStore(path=tmp_path / "ev.ndjson")
    obs = RedirectObservatory(
        evidence_store=store, node_id="dg-test", policy=RedirectPolicy.INSPECT_ONLY
    )
    result = obs.inspect("https://127.0.0.1/path?api_key=supersecret")
    assert result.error
    raw = (tmp_path / "ev.ndjson").read_text()
    assert "supersecret" not in raw
    assert "api_key" not in raw


def test_redact_preserves_path_only():
    assert _redact_url("https://h/x/y?q=1#f") == "https://h/x/y"


def test_connect_failure_surfaces_cleanly():
    ssrf = make_test_ssrf({"ok.test": ["1.1.1.1"]})
    client = PinnedHTTPClient(ssrf=ssrf, timeout_s=1.0)
    with patch(
        "dragon_gate.security.pinned_transport.socket.create_connection",
        side_effect=TimeoutError("timed out"),
    ):
        with pytest.raises(ConnectionError):
            client.request("GET", "http://ok.test/")
