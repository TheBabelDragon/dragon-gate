"""Single CLI namespace: dragon-gate <command>."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.table import Table

from dragon_gate import __version__
from dragon_gate.core.config import load_config, validate_config
from dragon_gate.core.health import collect_health
from dragon_gate.core.identity import load_or_create_identity
from dragon_gate.core.registry import build_default_registry
from dragon_gate.evidence.store import EvidenceStore
from dragon_gate.network.gateways import Gateway, GatewayRegistry, GatewayState
from dragon_gate.network.peers import PeerRegistry
from dragon_gate.network.routes import Route, RouteTable
from dragon_gate.transport.capabilities import report_transport_capabilities
from dragon_gate.web.dns_lab import DNSLaboratory
from dragon_gate.web.redirect import RedirectObservatory, RedirectPolicy
from dragon_gate.web.tls_lab import TLSLaboratory

app = typer.Typer(
    name="dragon-gate",
    help="DRAGON//GATE — Autonomous Network Foundation",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _out(data: Any, as_json: bool) -> None:
    if as_json:
        console.print_json(json.dumps(data, default=str))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                console.print(f"[bold]{k}[/]: {v}")
        else:
            console.print(data)


@app.command()
def status(
    json_out: bool = typer.Option(False, "--json", help="JSON output"),
    internet: bool = typer.Option(False, "--check-internet", help="Probe internet reachability"),
) -> None:
    """Show node identity, health, and capability summary."""
    ident = load_or_create_identity()
    reg = build_default_registry()
    health = collect_health(ident, capabilities=reg.names(), check_internet=internet)
    data = {
        "version": __version__,
        "node_id": ident.node_id,
        "public_key": ident.public_key_b64,
        "health": health.to_dict(),
        "capabilities": reg.report(),
        "transports": [c.to_dict() for c in report_transport_capabilities()],
    }
    if json_out:
        _out(data, True)
    else:
        console.print(f"[bold green]DRAGON//GATE[/] v{__version__}")
        console.print(f"Node ID : {ident.node_id}")
        console.print(f"Host    : {health.hostname}")
        console.print(f"Platform: {health.platform}")
        if health.internet_reachable is not None:
            state = "yes" if health.internet_reachable else "no"
            console.print(f"Internet: {state}")
        console.print(f"Capabilities: {', '.join(reg.names())}")


@app.command()
def doctor(
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Run local diagnostics and configuration validation."""
    cfg = load_config()
    issues = validate_config(cfg)
    ident = load_or_create_identity()
    health = collect_health(ident, check_internet=False)
    data = {
        "config_ok": len(issues) == 0,
        "config_issues": issues,
        "identity_ok": True,
        "node_id": ident.node_id,
        "interfaces": health.interfaces,
    }
    if json_out:
        _out(data, True)
    else:
        if issues:
            console.print("[red]Configuration issues:[/]")
            for i in issues:
                console.print(f"  • {i}")
            raise typer.Exit(1)
        console.print("[green]Configuration OK[/]")
        console.print(f"Node identity: {ident.node_id}")
        console.print(f"Interfaces discovered: {len(health.interfaces)}")


@app.command()
def inspect(
    url: str = typer.Argument(..., help="URL to inspect"),
    policy: str = typer.Option("INSPECT_ONLY", help="INSPECT_ONLY | FOLLOW_SAFE | SIMULATE"),
    json_out: bool = typer.Option(False, "--json"),
    allow_private: bool = typer.Option(False, "--allow-private"),
) -> None:
    """Redirect Observatory — inspect a URL without following unsafe redirects."""
    pol = RedirectPolicy(policy)
    obs = RedirectObservatory(policy=pol, allow_private=allow_private)
    result = obs.inspect(url)
    if json_out:
        _out(result.to_dict(), True)
    else:
        console.print(f"[bold]Inspect[/] {url}  (policy={pol.value})")
        for i, hop in enumerate(result.hops):
            status = hop.status if hop.status is not None else "—"
            console.print(f"  [{i}] {hop.url} → {status}")
            if hop.location:
                console.print(f"       Location: {hop.location}")
            if hop.error:
                console.print(f"       [red]{hop.error}[/]")
        if result.loop_detected:
            console.print("[red]Loop detected[/]")
        if result.downgrade_detected:
            console.print("[yellow]HTTPS downgrade detected[/]")
        if result.error:
            console.print(f"[red]{result.error}[/]")
            raise typer.Exit(2)


@app.command()
def trace(
    url: str = typer.Argument(...),
    json_out: bool = typer.Option(False, "--json"),
    allow_private: bool = typer.Option(False, "--allow-private"),
) -> None:
    """Follow safe redirects and show the full chain."""
    obs = RedirectObservatory(
        policy=RedirectPolicy.FOLLOW_SAFE, allow_private=allow_private
    )
    result = obs.trace(url)
    if json_out:
        _out(result.to_dict(), True)
    else:
        console.print(f"[bold]Trace[/] {url}")
        for i, hop in enumerate(result.hops):
            console.print(f"  [{i}] {hop.status} {hop.url}")
        if result.final_url:
            console.print(f"Final: {result.final_url}")
        if result.error:
            console.print(f"[red]{result.error}[/]")
            raise typer.Exit(2)


@app.command()
def dns(
    name: str = typer.Argument(...),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """DNS Laboratory — A/AAAA/CNAME inspection."""
    lab = DNSLaboratory()
    result = lab.inspect(name)
    if json_out:
        _out(result.to_dict(), True)
    else:
        console.print(f"[bold]DNS[/] {name}")
        for a in result.answers:
            if a.error:
                console.print(f"  {a.rdtype}: [red]{a.error}[/]")
            else:
                console.print(f"  {a.rdtype} (TTL={a.ttl}): {', '.join(a.data) or '—'}")


@app.command()
def tls(
    host: str = typer.Argument(...),
    port: int = typer.Option(443),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """TLS Laboratory — certificate and handshake diagnostics."""
    lab = TLSLaboratory()
    result = lab.inspect(host, port)
    if json_out:
        _out(result.to_dict(), True)
    else:
        console.print(f"[bold]TLS[/] {host}:{port}")
        if result.error:
            console.print(f"[red]{result.error}[/]")
            raise typer.Exit(2)
        console.print(f"  Version : {result.tls_version}")
        console.print(f"  Cipher  : {result.cipher}")
        console.print(f"  Hostname OK: {result.hostname_ok}")
        if result.expires_in_days is not None:
            console.print(f"  Expires in: {result.expires_in_days:.1f} days")
        for c in result.chain:
            console.print(f"  Subject : {c.subject}")
            console.print(f"  Issuer  : {c.issuer}")
            if c.san:
                console.print(f"  SAN     : {', '.join(c.san[:5])}")


@app.command("peers")
def peers_cmd(
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """List known peers (local registry)."""
    # In-memory for v0.1 demo; persistent store planned
    reg = PeerRegistry()
    data = [p.to_dict() for p in reg.list()]
    if json_out:
        _out(data, True)
    else:
        if not data:
            console.print("No peers enrolled yet.")
        else:
            for p in data:
                console.print(f"{p['node_id']}  trust={p['trust']}  reach={p['reachability']}")


@app.command("routes")
def routes_cmd(
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show route table."""
    table = RouteTable()
    data = [r.to_dict() for r in table.list()]
    if json_out:
        _out(data, True)
    else:
        if not data:
            console.print("No routes installed.")
        else:
            for r in data:
                console.print(f"{r['destination']} via {r['next_hop']} metric={r['metric']}")


@app.command("gateways")
def gateways_cmd(
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show gateway registry."""
    reg = GatewayRegistry()
    data = [g.to_dict() for g in reg.list()]
    if json_out:
        _out(data, True)
    else:
        if not data:
            console.print("No gateways registered.")
        else:
            for g in data:
                console.print(
                    f"{g['gateway_id']}  auth={g['authorized']}  state={g['state']}"
                )


evidence_app = typer.Typer(help="Evidence commands")
app.add_typer(evidence_app, name="evidence")


@evidence_app.command("verify")
def evidence_verify(
    path: Path = typer.Argument(..., exists=True),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Verify content hashes in an NDJSON evidence file."""
    ok, fail = EvidenceStore.verify_file(path)
    data = {"ok": ok, "fail": fail, "path": str(path)}
    if json_out:
        _out(data, True)
    else:
        console.print(f"Verified: {ok} ok, {fail} failed")
        if fail:
            raise typer.Exit(1)


@evidence_app.command("replay")
def evidence_replay(
    path: Path = typer.Argument(..., exists=True),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Load and display evidence events (deterministic replay of stored records)."""
    events = EvidenceStore.load_ndjson(path)
    data = [e.model_dump() for e in events]
    if json_out:
        _out(data, True)
    else:
        console.print(f"{len(events)} events")
        for e in events[:20]:
            console.print(f"  {e.sequence} {e.event_type} {e.event_id[:8]}…")


config_app = typer.Typer(help="Configuration commands")
app.add_typer(config_app, name="config")


@config_app.command("validate")
def config_validate(
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    cfg = load_config()
    issues = validate_config(cfg)
    if json_out:
        _out({"ok": len(issues) == 0, "issues": issues}, True)
    else:
        if issues:
            for i in issues:
                console.print(f"[red]• {i}[/]")
            raise typer.Exit(1)
        console.print("[green]config valid[/]")


@app.command("lab")
def lab_launch(
    name: str = typer.Argument("redirect", help="redirect | dns | tls"),
) -> None:
    """Launch a laboratory helper (placeholder for interactive lab)."""
    console.print(f"Lab '{name}' — use the dedicated commands (inspect/dns/tls) in v0.1")


if __name__ == "__main__":
    app()
