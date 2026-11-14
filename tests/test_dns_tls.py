"""DNS and TLS laboratory structure tests (offline-safe)."""

from dragon_gate.web.dns_lab import DNSLaboratory, DNSAnswer
from dragon_gate.web.tls_lab import TLSResult, CertInfo


def test_dns_answer_structure():
    a = DNSAnswer(name="example.com", rdtype="A", data=["93.184.216.34"], ttl=300)
    d = a.to_dict()
    assert d["rdtype"] == "A"
    assert d["data"] == ["93.184.216.34"]


def test_tls_result_structure():
    r = TLSResult(host="example.com", connected=False, error="timeout")
    d = r.to_dict()
    assert d["host"] == "example.com"
    assert d["error"] == "timeout"
