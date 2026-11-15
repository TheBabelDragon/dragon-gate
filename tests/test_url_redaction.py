"""URL redaction must strip credentials and query strings from evidence."""

from dragon_gate.web.redirect import _redact_url


def test_strips_query_string():
    red = _redact_url("https://api.example.com/v1?token=secret&x=1")
    assert "token" not in red
    assert "secret" not in red
    assert "?" not in red
    assert red == "https://api.example.com/v1"


def test_strips_fragment():
    red = _redact_url("https://example.com/path#section")
    assert "#" not in red


def test_strips_userinfo_via_parse():
    # urlparse may place userinfo in netloc; hostname extraction drops it
    red = _redact_url("https://user:pass@example.com/x")
    assert "user" not in red
    assert "pass" not in red
    assert red.startswith("https://example.com")
