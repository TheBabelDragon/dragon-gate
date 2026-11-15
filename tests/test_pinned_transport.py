"""Connection pinning — validated IP is what the socket uses."""

from unittest.mock import MagicMock, patch

import pytest

from dragon_gate.security.pinned_transport import PinnedHTTPClient, make_test_ssrf
from dragon_gate.security.ssrf import SSRFError


def test_request_rejects_before_connect_when_dns_private():
    ssrf = make_test_ssrf({"evil.test": ["127.0.0.1"]})
    client = PinnedHTTPClient(ssrf=ssrf, timeout_s=2.0)
    with pytest.raises(SSRFError):
        client.request("GET", "https://evil.test/")


def test_request_rejects_mixed_answers_before_connect():
    ssrf = make_test_ssrf({"evil.test": ["1.1.1.1", "10.0.0.1"]})
    client = PinnedHTTPClient(ssrf=ssrf, timeout_s=2.0)
    with pytest.raises(SSRFError):
        client.request("GET", "https://evil.test/")


def test_connect_uses_validated_literal(monkeypatch):
    """Socket create_connection must receive the validated IP, not the hostname."""
    ssrf = make_test_ssrf({"ok.test": ["203.0.113.10"]})
    client = PinnedHTTPClient(ssrf=ssrf, timeout_s=2.0)

    seen: list[tuple] = []

    def fake_create_connection(address, timeout=None):
        seen.append(address)
        raise OSError("stop after observing destination")

    with patch("dragon_gate.security.pinned_transport.socket.create_connection", fake_create_connection):
        with pytest.raises(ConnectionError):
            client.request("GET", "http://ok.test/path")

    assert seen, "create_connection was never called"
    host, port = seen[0]
    assert host == "203.0.113.10"
    assert port == 80
