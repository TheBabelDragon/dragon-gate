"""DNS rebinding adversarial suite — connection must use validated addresses only."""

import pytest

from dragon_gate.security.pinned_transport import make_test_ssrf
from dragon_gate.security.ssrf import SSRFError, SSRFProtection, resolve_host


def test_public_then_private_answer_rejected():
    ssrf = make_test_ssrf({"evil.test": ["1.1.1.1", "10.0.0.5"]})
    with pytest.raises(SSRFError, match="mixed|private|rebinding"):
        ssrf.resolve("evil.test")


def test_private_only_answer_rejected():
    ssrf = make_test_ssrf({"evil.test": ["192.168.1.10"]})
    with pytest.raises(SSRFError):
        ssrf.resolve("evil.test")


def test_ipv6_loopback_answer_rejected():
    ssrf = make_test_ssrf({"evil.test": ["::1"]})
    with pytest.raises(SSRFError):
        ssrf.resolve("evil.test")


def test_ipv4_mapped_loopback_answer_rejected():
    ssrf = make_test_ssrf({"evil.test": ["::ffff:127.0.0.1"]})
    with pytest.raises(SSRFError):
        ssrf.resolve("evil.test")


def test_dns_failure():
    ssrf = make_test_ssrf({})
    with pytest.raises(SSRFError, match="DNS resolution failed"):
        ssrf.resolve("missing.test")


def test_empty_dns_answer():
    ssrf = make_test_ssrf({"empty.test": []})
    with pytest.raises(SSRFError):
        ssrf.resolve("empty.test")


def test_malformed_dns_answer():
    ssrf = make_test_ssrf({"bad.test": ["not-an-ip"]})
    with pytest.raises(SSRFError):
        ssrf.resolve("bad.test")


def test_multiple_public_a_aaaa_ok():
    ssrf = make_test_ssrf(
        {"ok.test": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]}
    )
    result = ssrf.resolve("ok.test")
    assert len(result.addresses) == 2


def test_resolution_uses_injected_answers_not_system():
    """Critical: injected resolver answers are what validation sees."""
    calls: list[str] = []

    def tracking_resolver(hostname: str) -> list[str]:
        calls.append(hostname)
        return ["1.1.1.1"]

    ssrf = SSRFProtection(resolver=tracking_resolver)
    r = ssrf.resolve("tracked.example")
    assert r.addresses == ["1.1.1.1"]
    assert calls == ["tracked.example"]


def test_allow_private_permits_rfc1918_only():
    ssrf = make_test_ssrf({"lan.test": ["10.0.0.5"]}, allow_private=True)
    r = ssrf.resolve("lan.test")
    assert r.addresses == ["10.0.0.5"]

    ssrf2 = make_test_ssrf({"loop.test": ["127.0.0.1"]}, allow_private=True)
    with pytest.raises(SSRFError):
        ssrf2.resolve("loop.test")
