"""Aurora integration boundary.

Aurora owns destination routing. Dragon Gate provides the operational,
security, and diagnostic surface around it. Egress remains disabled by default.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol


@dataclass
class AuroraRouteDiagnosis:
    target: str
    resolved: bool
    routes: list[dict[str, Any]] = field(default_factory=list)
    gateways: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuroraAdapter(Protocol):
    def resolve_destination(self, target: str) -> AuroraRouteDiagnosis: ...

    def list_gateways(self) -> list[dict[str, Any]]: ...

    def health(self) -> dict[str, Any]: ...


class NullAuroraAdapter:
    """Default adapter when Aurora is not configured."""

    def resolve_destination(self, target: str) -> AuroraRouteDiagnosis:
        return AuroraRouteDiagnosis(
            target=target,
            resolved=False,
            error="Aurora adapter not configured",
            notes="Set aurora.enabled and endpoints in config to activate",
        )

    def list_gateways(self) -> list[dict[str, Any]]:
        return []

    def health(self) -> dict[str, Any]:
        return {"status": "disabled", "egress_enabled": False}


class HttpAuroraAdapter:
    """Minimal HTTP client against Aurora diagnostics endpoints.

    Preserves Aurora's existing contracts:
    - Authenticated gateway capability claims
    - Policy-first routes
    - Connection-time deny_private
    - Egress relay not implemented by default
    """

    def __init__(self, base_url: str, egress_enabled: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.egress_enabled = egress_enabled

    def resolve_destination(self, target: str) -> AuroraRouteDiagnosis:
        import httpx

        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.get(
                    f"{self.base_url}/comms/destinations/resolve",
                    params={"target": target},
                )
                data = r.json()
                return AuroraRouteDiagnosis(
                    target=target,
                    resolved=r.status_code == 200,
                    routes=data.get("routes", []) if isinstance(data, dict) else [],
                    notes="via Aurora HTTP adapter",
                )
        except Exception as e:
            return AuroraRouteDiagnosis(
                target=target, resolved=False, error=str(e)
            )

    def list_gateways(self) -> list[dict[str, Any]]:
        import httpx

        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.get(f"{self.base_url}/comms/gateways")
                data = r.json()
                return data if isinstance(data, list) else data.get("gateways", [])
        except Exception:
            return []

    def health(self) -> dict[str, Any]:
        return {
            "status": "configured",
            "base_url": self.base_url,
            "egress_enabled": self.egress_enabled,
        }
