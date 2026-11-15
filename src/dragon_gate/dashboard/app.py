"""Minimal FastAPI dashboard — persistent peer state, topology, labs.

Install: pip install -e ".[dashboard]"
Run: uvicorn dragon_gate.dashboard.app:app --host 127.0.0.1 --port 8080
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, HTTPException
except ImportError as e:
    raise ImportError(
        "Dashboard requires the 'dashboard' extra: pip install -e '.[dashboard]'"
    ) from e

from dragon_gate import __version__
from dragon_gate.core.config import load_config
from dragon_gate.core.health import collect_health
from dragon_gate.core.identity import load_or_create_identity
from dragon_gate.core.registry import build_default_registry
from dragon_gate.network.gateways import GatewayRegistry
from dragon_gate.network.routes import RouteTable
from dragon_gate.runtime.store import PeerStore
from dragon_gate.transport.capabilities import report_transport_capabilities

app = FastAPI(title="DRAGON//GATE", version=__version__)


def _store() -> PeerStore:
    cfg = load_config()
    return PeerStore(Path(cfg.data_dir) / "peers.db")


@app.get("/api/status")
def api_status() -> dict[str, Any]:
    ident = load_or_create_identity()
    reg = build_default_registry()
    health = collect_health(ident, capabilities=reg.names())
    store = _store()
    peers = store.list_peers()
    store.close()
    return {
        "version": __version__,
        "node_id": ident.node_id,
        "public_key": ident.public_key_b64,
        "health": health.to_dict(),
        "capabilities": reg.report(),
        "transports": [c.to_dict() for c in report_transport_capabilities()],
        "states": {
            "discovered": sum(1 for p in peers if p["trust"] == "discovered"),
            "authenticated": sum(
                1 for p in peers if p["trust"] in ("authenticated", "authorized")
            ),
            "authorized": sum(1 for p in peers if p["trust"] == "authorized"),
            "reachable": sum(1 for p in peers if p["reachability"] == "reachable"),
            "internet_connected": health.internet_reachable,
        },
    }


@app.get("/api/peers")
def api_peers() -> list[dict[str, Any]]:
    store = _store()
    data = store.list_peers()
    store.close()
    return data


@app.get("/api/topology")
def api_topology() -> dict[str, Any]:
    ident = load_or_create_identity()
    store = _store()
    peers = store.list_peers()
    data = {
        "local_node_id": ident.node_id,
        "peers": peers,
        "authenticated_peers": [
            p for p in peers if p["trust"] in ("authenticated", "authorized")
        ],
        "authorized_peers": [p for p in peers if p["trust"] == "authorized"],
        "routes": store.list_routes(),
        "gateways": store.list_gateways(),
    }
    store.close()
    return data


@app.get("/api/routes")
def api_routes() -> list[dict[str, Any]]:
    store = _store()
    routes = store.list_routes()
    store.close()
    if routes:
        return routes
    return [r.to_dict() for r in RouteTable().list()]


@app.get("/api/gateways")
def api_gateways() -> list[dict[str, Any]]:
    store = _store()
    gws = store.list_gateways()
    store.close()
    if gws:
        return gws
    return [g.to_dict() for g in GatewayRegistry().list()]


@app.post("/api/peers/{node_id}/authorize")
def api_authorize(node_id: str) -> dict[str, str]:
    """Local-only admin: explicit authorization."""
    store = _store()
    p = store.get_peer(node_id)
    if not p:
        store.close()
        raise HTTPException(404, "unknown peer")
    if p["trust"] not in ("authenticated", "authorized"):
        store.close()
        raise HTTPException(400, "peer must be authenticated first")
    store.set_trust(node_id, "authorized")
    store.record_observation(node_id, "authorized")
    store.close()
    return {"node_id": node_id, "trust": "authorized"}


@app.post("/api/peers/{node_id}/revoke")
def api_revoke(node_id: str) -> dict[str, str]:
    store = _store()
    if not store.get_peer(node_id):
        store.close()
        raise HTTPException(404, "unknown peer")
    store.set_trust(node_id, "revoked")
    store.record_observation(node_id, "revoked")
    store.close()
    return {"node_id": node_id, "trust": "revoked"}


@app.get("/")
def index() -> dict[str, str]:
    return {
        "service": "DRAGON//GATE",
        "version": __version__,
        "docs": "/docs",
        "note": "Local-first. Bind to 127.0.0.1. Authenticated ≠ authorized.",
    }
