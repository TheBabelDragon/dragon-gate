"""Minimal FastAPI dashboard — node identity, interfaces, peers, gateways, labs.

Install with: pip install -e ".[dashboard]"
Run: uvicorn dragon_gate.dashboard.app:app --reload
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI
except ImportError as e:
    raise ImportError(
        "Dashboard requires the 'dashboard' extra: pip install -e '.[dashboard]'"
    ) from e

from dragon_gate import __version__
from dragon_gate.core.health import collect_health
from dragon_gate.core.identity import load_or_create_identity
from dragon_gate.core.registry import build_default_registry
from dragon_gate.network.peers import PeerRegistry
from dragon_gate.network.gateways import GatewayRegistry
from dragon_gate.network.routes import RouteTable
from dragon_gate.transport.capabilities import report_transport_capabilities

app = FastAPI(title="DRAGON//GATE", version=__version__)


@app.get("/api/status")
def api_status() -> dict[str, Any]:
    ident = load_or_create_identity()
    reg = build_default_registry()
    health = collect_health(ident, capabilities=reg.names())
    return {
        "version": __version__,
        "node_id": ident.node_id,
        "public_key": ident.public_key_b64,
        "health": health.to_dict(),
        "capabilities": reg.report(),
        "transports": [c.to_dict() for c in report_transport_capabilities()],
        "states": {
            "connected": None,
            "discovered": 0,
            "authenticated": 0,
            "authorized": 0,
            "reachable": 0,
            "internet_connected": health.internet_reachable,
        },
    }


@app.get("/api/peers")
def api_peers() -> list[dict[str, Any]]:
    return [p.to_dict() for p in PeerRegistry().list()]


@app.get("/api/routes")
def api_routes() -> list[dict[str, Any]]:
    return [r.to_dict() for r in RouteTable().list()]


@app.get("/api/gateways")
def api_gateways() -> list[dict[str, Any]]:
    return [g.to_dict() for g in GatewayRegistry().list()]


@app.get("/")
def index() -> dict[str, str]:
    return {
        "service": "DRAGON//GATE",
        "version": __version__,
        "docs": "/docs",
        "note": "Local-first operational interface. States (connected/discovered/authenticated/authorized/reachable/internet-connected) are distinct.",
    }
