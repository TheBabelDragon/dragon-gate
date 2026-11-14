"""Configuration management with versioned schemas."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class NetworkConfig(BaseModel):
    listen_interfaces: list[str] = Field(default_factory=lambda: ["auto"])
    allow_private_targets: bool = False
    default_timeout_s: float = 10.0
    max_redirects: int = 10


class SecurityConfig(BaseModel):
    require_peer_auth: bool = True
    allow_unauthenticated_discovery: bool = False
    evidence_required: bool = True


class AuroraConfig(BaseModel):
    enabled: bool = False
    endpoints: list[str] = Field(default_factory=list)
    egress_enabled: bool = False  # always default off


class GateConfig(BaseModel):
    schema_version: str = "1.0.0"
    node_name: str | None = None
    data_dir: str = Field(
        default_factory=lambda: str(
            Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
            / "dragon-gate"
        )
    )
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    aurora: AuroraConfig = Field(default_factory=AuroraConfig)
    extra: dict[str, Any] = Field(default_factory=dict)


def default_config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "dragon-gate" / "config.yaml"


def load_config(path: Path | None = None) -> GateConfig:
    path = path or default_config_path()
    if not path.exists():
        cfg = GateConfig()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(cfg.model_dump(), sort_keys=False))
        return cfg
    data = yaml.safe_load(path.read_text()) or {}
    return GateConfig.model_validate(data)


def validate_config(cfg: GateConfig) -> list[str]:
    """Return list of validation issues (empty = ok)."""
    issues: list[str] = []
    if cfg.aurora.egress_enabled and not cfg.aurora.endpoints:
        issues.append("aurora.egress_enabled is true but no endpoints configured")
    if cfg.network.max_redirects < 1:
        issues.append("network.max_redirects must be >= 1")
    return issues
