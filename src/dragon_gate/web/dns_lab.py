"""DNS Laboratory — A/AAAA, CNAME, TTL, resolver comparison."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

import dns.exception
import dns.resolver


@dataclass
class DNSAnswer:
    name: str
    rdtype: str
    data: list[str] = field(default_factory=list)
    ttl: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DNSResult:
    query: str
    answers: list[DNSAnswer] = field(default_factory=list)
    resolver: str = "system"
    timing_ms: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "answers": [a.to_dict() for a in self.answers],
            "resolver": self.resolver,
            "timing_ms": self.timing_ms,
            "error": self.error,
        }


class DNSLaboratory:
    def __init__(self, nameservers: list[str] | None = None) -> None:
        self.nameservers = nameservers

    def _resolver(self) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver()
        if self.nameservers:
            r.nameservers = self.nameservers
        return r

    def query(self, name: str, rdtype: str = "A") -> DNSAnswer:
        ans = DNSAnswer(name=name, rdtype=rdtype)
        try:
            resolver = self._resolver()
            response = resolver.resolve(name, rdtype)
            ans.ttl = response.rrset.ttl if response.rrset else None
            ans.data = [str(r) for r in response]
        except dns.resolver.NXDOMAIN:
            ans.error = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            ans.error = "NoAnswer"
        except dns.exception.Timeout:
            ans.error = "timeout"
        except Exception as e:
            ans.error = str(e)
        return ans

    def inspect(self, name: str) -> DNSResult:
        t0 = time.monotonic()
        result = DNSResult(query=name)
        for rdtype in ("A", "AAAA", "CNAME"):
            result.answers.append(self.query(name, rdtype))
        result.timing_ms = (time.monotonic() - t0) * 1000
        return result

    def compare_resolvers(
        self, name: str, resolvers: list[list[str]]
    ) -> list[DNSResult]:
        """Compare answers across multiple resolver sets."""
        out: list[DNSResult] = []
        for ns in resolvers:
            lab = DNSLaboratory(nameservers=ns)
            r = lab.inspect(name)
            r.resolver = ",".join(ns)
            out.append(r)
        return out
