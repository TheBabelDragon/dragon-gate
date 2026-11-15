"""FastAPI dashboard — persistent peers, local admin token + CSRF checks.

Bind to 127.0.0.1 by default. Admin token via DG_ADMIN_TOKEN env or config.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Header, HTTPException, Request
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

# Ephemeral CSRF secret for browser POSTs (process-local)
_CSRF_SECRET = secrets.token_urlsafe(32)


def _admin_token() -> str:
    return os.environ.get("DG_ADMIN_TOKEN", "")


def _store() -> PeerStore:
    cfg = load_config()
    return PeerStore(Path(cfg.data_dir) / "peers.db")


def _require_admin(
    request: Request,
    authorization: str | None,
    x_csrf_token: str | None,
) -> None:
    token = _admin_token()
    if not token:
        raise HTTPException(503, "admin token not configured (set DG_ADMIN_TOKEN)")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    if not secrets.compare_digest(authorization[7:], token):
        raise HTTPException(403, "invalid token")
    # CSRF: require matching header for cookie-like browser posts
    origin = request.headers.get("origin")
    host = request.headers.get("host", "")
    if origin:
        # Origin must match Host when present
        if host and origin.rstrip("/").endswith(host.split(":")[0]) is False:
            # allow localhost variants
            if "127.0.0.1" not in origin and "localhost" not in origin:
                raise HTTPException(403, "origin rejected")
        if not x_csrf_token or not secrets.compare_digest(x_csrf_token, _CSRF_SECRET):
            # Accept if Authorization is Bearer (API client) without CSRF for non-browser
            # Still require CSRF when Origin is set (browser)
            raise HTTPException(403, "csrf required")


@app.get("/api/csrf")
def api_csrf() -> dict[str, str]:
    return {"csrf_token": _CSRF_SECRET}


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
    # Never expose private keys (none stored in peer records by design)
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
def api_authorize(
    node_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
    x_csrf_token: str | None = Header(default=None),
) -> dict[str, str]:
    _require_admin(request, authorization, x_csrf_token)
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
def api_revoke(
    node_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
    x_csrf_token: str | None = Header(default=None),
) -> dict[str, str]:
    _require_admin(request, authorization, x_csrf_token)
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
        "note": "Local-first. Bind 127.0.0.1. Admin requires DG_ADMIN_TOKEN + CSRF when Origin set.",
    }
