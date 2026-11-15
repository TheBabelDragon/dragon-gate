"""SSRF destination rejection, address classification, rebinding protection."""

import pytest

from dragon_gate.security.ssrf import (
    SSRFError,
    SSRFProtection,
    classify_address,
    is_blocked_destination,
    normalize_hostname,
    parse_ip,
    validate_resolved_addresses,
)


def test_loopback_blocked():
    assert is_blocked_destination("127.0.0.1")
    assert is_blocked_destination("::1")
    assert is_blocked_destination("127.0.0.2")


def test_private_blocked():
    assert is_blocked_destination("10.0.0.1")
    assert is_blocked_destination("192.168.1.1")
    assert is_blocked_destination("172.16.0.5")


def test_metadata_blocked():
    assert is_blocked_destination("169.254.169.254")
    assert is_blocked_destination("metadata.google.internal")


def test_public_allowed():
    assert not is_blocked_destination("1.1.1.1")
    assert not is_blocked_destination("8.8.8.8")


def test_ipv6_ula_blocked():
    assert is_blocked_destination("fd12:3456:789a::1")


def test_ipv6_link_local_blocked():
    assert is_blocked_destination("fe80::1")


def test_ipv4_mapped_loopback_blocked():
    # ::ffff:127.0.0.1
    assert is_blocked_destination("::ffff:127.0.0.1")


def test_allow_private_still_blocks_loopback():
    assert is_blocked_destination("127.0.0.1", allow_private=True)
    assert is_blocked_destination("::1", allow_private=True)
    assert is_blocked_destination("169.254.169.254", allow_private=True)
    assert not is_blocked_destination("10.0.0.1", allow_private=True)


def test_trailing_dot_and_idna():
    assert normalize_hostname("Example.COM.") == "example.com"


def test_scoped_address_rejected():
    with pytest.raises(SSRFError, match="scoped"):
        parse_ip("fe80::1%eth0")


def test_ssrf_check_url():
    ssrf = SSRFProtection()
    with pytest.raises(SSRFError):
        ssrf.check_url("http://127.0.0.1/")
    with pytest.raises(SSRFError):
        ssrf.check_url("http://169.254.169.254/")
    with pytest.raises(SSRFError):
        ssrf.check_url("http://user:pass@example.com/")
    ssrf.check_url("https://example.com/")


def test_validate_empty_dns():
    with pytest.raises(SSRFError, match="empty"):
        validate_resolved_addresses("example.com", [])


def test_validate_private_in_answers():
    with pytest.raises(SSRFError, match="rebinding"):
        validate_resolved_addresses("evil.example", ["127.0.0.1"])


def test_validate_mixed_public_private():
    with pytest.raises(SSRFError, match="mixed"):
        validate_resolved_addresses("evil.example", ["1.1.1.1", "10.0.0.1"])


def test_validate_private_hidden_among_public():
    with pytest.raises(SSRFError):
        validate_resolved_addresses(
            "evil.example", ["8.8.8.8", "192.168.0.1", "1.1.1.1"]
        )


def test_validate_all_public_ok():
    addrs = validate_resolved_addresses("example.com", ["93.184.216.34", "1.2.3.4"])
    assert "93.184.216.34" in addrs


def test_ipv4_mapped_in_answers():
    with pytest.raises(SSRFError):
        validate_resolved_addresses("evil.example", ["::ffff:127.0.0.1"])


def test_classify_global():
    assert classify_address(parse_ip("1.1.1.1")) == "global"
