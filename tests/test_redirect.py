"""Redirect Observatory — synthetic scenarios via httpx mock patterns.

These tests use controlled fixtures; CI does not depend on public websites.
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from dragon_gate.web.redirect import RedirectObservatory, RedirectPolicy


def _mock_response(status: int, location: str | None = None, headers: dict | None = None):
    resp = MagicMock()
    resp.status_code = status
    hdrs = dict(headers or {})
    if location:
        hdrs["location"] = location
    resp.headers = hdrs
    resp.content = b""
    return resp


def test_inspect_only_does_not_follow():
    obs = RedirectObservatory(policy=RedirectPolicy.INSPECT_ONLY)
    with patch("httpx.Client") as Client:
        client = Client.return_value.__enter__.return_value
        client.request.return_value = _mock_response(301, "https://example.com/b")
        result = obs.inspect("https://example.com/a")
    assert len(result.hops) == 1
    assert result.hops[0].status == 301
    assert result.final_url == "https://example.com/a"


def test_redirect_loop_detected():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE, max_redirects=5)
    with patch("httpx.Client") as Client:
        client = Client.return_value.__enter__.return_value
        # A → B → A
        client.request.side_effect = [
            _mock_response(302, "https://example.com/b"),
            _mock_response(302, "https://example.com/a"),
        ]
        result = obs.inspect("https://example.com/a")
    assert result.loop_detected


def test_https_downgrade_detected():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE)
    with patch("httpx.Client") as Client:
        client = Client.return_value.__enter__.return_value
        client.request.return_value = _mock_response(301, "http://example.com/insecure")
        result = obs.inspect("https://example.com/")
    assert result.downgrade_detected
    assert result.error and "downgrade" in result.error.lower()


def test_ssrf_blocks_private_redirect_target():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE)
    with patch("httpx.Client") as Client:
        client = Client.return_value.__enter__.return_value
        client.request.return_value = _mock_response(302, "http://127.0.0.1/admin")
        result = obs.inspect("https://example.com/")
    assert result.error and "blocked" in result.error.lower()


def test_excessive_depth():
    obs = RedirectObservatory(policy=RedirectPolicy.FOLLOW_SAFE, max_redirects=2)
    with patch("httpx.Client") as Client:
        client = Client.return_value.__enter__.return_value
        client.request.side_effect = [
            _mock_response(301, "https://example.com/1"),
            _mock_response(301, "https://example.com/2"),
            _mock_response(301, "https://example.com/3"),
        ]
        result = obs.inspect("https://example.com/0")
    assert result.excessive_depth
