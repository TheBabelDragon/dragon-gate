"""Health and diagnostics collection."""

from __future__ import annotations

import platform
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from dragon_gate import __version__
from dragon_gate.core.identity import NodeIdentity


@dataclass
class HealthReport:
    node_id: str
    version: str
    hostname: str
    platform: str
    python: str
    timestamp: float
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    internet_reachable: bool | None = None
    capabilities: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _list_interfaces() -> list[dict[str, Any]]:
    """Best-effort interface discovery without privileged access."""
    results: list[dict[str, Any]] = []
    try:
        import psutil  # optional

        for name, addrs in psutil.net_if_addrs().items():
            entry: dict[str, Any] = {"name": name, "addresses": []}
            for a in addrs:
                entry["addresses"].append(
                    {"family": str(a.family), "address": a.address, "netmask": a.netmask}
                )
            results.append(entry)
    except ImportError:
        # Fallback: hostname + primary address
        try:
            hostname = socket.gethostname()
            addr = socket.gethostbyname(hostname)
            results.append(
                {"name": "primary", "addresses": [{"family": "AF_INET", "address": addr}]}
            )
        except Exception:
            pass
    return results


def collect_health(
    identity: NodeIdentity,
    capabilities: list[str] | None = None,
    check_internet: bool = False,
) -> HealthReport:
    report = HealthReport(
        node_id=identity.node_id,
        version=__version__,
        hostname=socket.gethostname(),
        platform=platform.platform(),
        python=platform.python_version(),
        timestamp=time.time(),
        interfaces=_list_interfaces(),
        capabilities=capabilities or [],
    )
    if check_internet:
        # Explicit optional probe — never assumed
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=2.0).close()
            report.internet_reachable = True
        except OSError:
            report.internet_reachable = False
    return report
