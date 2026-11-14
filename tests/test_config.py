"""Configuration validation and migration surface."""

from dragon_gate.core.config import GateConfig, validate_config


def test_default_config_valid():
    cfg = GateConfig()
    assert validate_config(cfg) == []


def test_egress_without_endpoints_invalid():
    cfg = GateConfig()
    cfg.aurora.egress_enabled = True
    issues = validate_config(cfg)
    assert any("egress" in i for i in issues)
