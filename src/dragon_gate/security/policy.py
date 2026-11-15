"""Security policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityPolicy:
    require_peer_auth: bool = True
    allow_private_targets: bool = False
    allow_http_downgrade: bool = False
    max_redirect_depth: int = 10
    block_metadata_services: bool = True
    extra: dict[str, Any] = field(default_factory=dict)


def evaluate_policy(policy: SecurityPolicy, context: dict[str, Any]) -> list[str]:
    """Return list of policy violations (empty = allow)."""
    violations: list[str] = []
    if policy.require_peer_auth and context.get("peer_authenticated") is False:
        violations.append("peer not authenticated")
    if not policy.allow_private_targets and context.get("target_is_private"):
        violations.append("private target blocked by policy")
    if not policy.allow_http_downgrade and context.get("https_downgrade"):
        violations.append("HTTPS downgrade blocked by policy")
    depth = context.get("redirect_depth", 0)
    if depth > policy.max_redirect_depth:
        violations.append(f"redirect depth {depth} exceeds limit {policy.max_redirect_depth}")
    return violations
