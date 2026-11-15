"""Redirect Observatory — policy, SSRF, downgrade, depth, pinning integration."""

from unittest.mock import MagicMock, patch

import pytest

from dragon_gate.security.pinned_transport import PinnedResponse, make_test_ssrf
from dragon_gate.security.ssrf import SSRFError
from dragon_gate.web.redirect import RedirectObservatory, RedirectPolicy


def _pinned(
    status: int,
    location: str | None = None,
    connected: str = "93.184.216.34",
    dns: list[str] | None = None,
):
    headers = {}
    if location:
        headers["location"] = location
    return PinnedResponse(
        status_code=status,
        headers=headers,
        content=b"",
        url="https://example.com/",
        resolved_addresses=dns or [connected],
        connected_address=connected,
        timing_ms=1.0,
    )


def test_inspect_only_does_not_follow():
    obs = RedirectObservatory(policy=RedirectPolicy.INSPECT_ONLY)
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()
        with patch(
            "dragon_gate.web.redirect.PinnedHTTPClient"
        ) as Client:
            inst = Client.return_value
            inst.request.return_value = _pinned(301, "https://example.com/b")
            result = obs.inspect("https://example.com/a")
    assert len(result.hops) == 1
    assert result.hops[0].status == 301
    assert result.final_url == "https://example.com/a"


def test_redirect_loop_detected():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE, max_redirects=5)
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()
        with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
            inst = Client.return_value
            inst.request.side_effect = [
                _pinned(302, "https://example.com/b"),
                _pinned(302, "https://example.com/a"),
            ]
            result = obs.inspect("https://example.com/a")
    assert result.loop_detected


def test_https_downgrade_detected():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE)
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()
        with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
            inst = Client.return_value
            inst.request.return_value = _pinned(301, "http://example.com/insecure")
            result = obs.inspect("https://example.com/")
    assert result.downgrade_detected
    assert result.error and "downgrade" in result.error.lower()


def test_ssrf_blocks_private_redirect_target():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE)
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()

        def check(url: str) -> None:
            if "127.0.0.1" in url:
                raise SSRFError("destination blocked", reason="blocked")

        ssrf.check_url.side_effect = check
        with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
            inst = Client.return_value
            inst.request.return_value = _pinned(302, "https://127.0.0.1/admin")
            result = obs.inspect("https://example.com/")
    assert result.error and "blocked" in result.error.lower()


def test_excessive_depth():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE, max_redirects=2)
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()
        with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
            inst = Client.return_value
            inst.request.side_effect = [
                _pinned(301, "https://example.com/1"),
                _pinned(301, "https://example.com/2"),
                _pinned(301, "https://example.com/3"),
            ]
            result = obs.inspect("https://example.com/0")
    assert result.excessive_depth or (
        result.error and "max redirects" in (result.error or "").lower()
    )


def test_unsupported_scheme_on_redirect():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE)
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()
        with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
            inst = Client.return_value
            inst.request.return_value = _pinned(302, "ftp://files.example/x")
            result = obs.inspect("https://example.com/")
    assert result.error and "scheme" in result.error.lower()


def test_userinfo_rejected_on_start():
    obs = RedirectObservatory()
    result = obs.inspect("https://user:pass@example.com/")
    assert result.error and ("userinfo" in result.error.lower() or "credential" in result.error.lower() or "blocked" in result.error.lower() or "not allowed" in result.error.lower())


def test_connected_address_recorded():
    obs = RedirectObservatory(policy=RedirectPolicy.INSPECT_ONLY)
    with patch.object(obs, "ssrf") as ssrf:
        ssrf.check_url = MagicMock()
        with patch("dragon_gate.web.redirect.PinnedHTTPClient") as Client:
            inst = Client.return_value
            inst.request.return_value = _pinned(200, connected="93.184.216.34")
            result = obs.inspect("https://example.com/")
    assert result.hops[0].connected_address == "93.184.216.34"
    assert "93.184.216.34" in result.hops[0].dns
