"""SSRF destination rejection and rebinding protection."""

import pytest

from dragon_gate.security.ssrf import SSRFProtection, is_blocked_destination


def test_loopback_blocked():
    assert is_blocked_destination("127.0.0.1")
    assert is_blocked_destination("::1")


def test_private_blocked():
    assert is_blocked_destination("10.0.0.1")
    assert is_blocked_destination("192.168.1.1")
    assert is_blocked_destination("172.16.0.5")


def test_metadata_blocked():
    assert is_blocked_destination("169.254.169.254")


def test_public_allowed():
    assert not is_blocked_destination("1.1.1.1")
    assert not is_blocked_destination("8.8.8.8")


def test_ssrf_check_url():
    ssrf = SSRFProtection()
    with pytest.raises(ValueError):
        ssrf.check_url("http://127.0.0.1/")
    with pytest.raises(ValueError):
        ssrf.check_url("http://169.254.169.254/")
    ssrf.check_url("https://example.com/")  # should not raise


def test_rebinding_protection():
    ssrf = SSRFProtection()
    with pytest.raises(ValueError, match="rebinding"):
        ssrf.check_resolved("evil.example", ["127.0.0.1"])
