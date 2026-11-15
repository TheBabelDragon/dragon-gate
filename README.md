# DRAGON//GATE v0.1

**Autonomous Network Foundation for the BabelDragon ecosystem.**

Dragon Gate is the security, networking, diagnostics, and orchestration distribution for BabelDragon.  
Its long-term objective is progressive independence from conventional ISP infrastructure while remaining useful as a security and diagnostics workstation today.

> This is **not** a Kali clone or a bag of unrelated utilities.  
> It is a coherent, modular network operating environment.

## Status (v0.1)

| Area | State |
|------|-------|
| CLI (`dragon-gate`) | Implemented |
| Node identity (Ed25519) | Implemented |
| Evidence / NDJSON contract | Implemented |
| Redirect Observatory | Implemented (synthetic + live) |
| DNS Laboratory | Implemented |
| TLS Laboratory | Implemented |
| Peer / route / gateway models | Implemented (deterministic tests) |
| Local autonomy foundations | Implemented |
| Aurora adapter contracts | Documented + stub adapters |
| Arch packaging | PKGBUILD present |
| Dashboard | Minimal local-first scaffold |
| Full multi-node mesh | Planned (v0.2+) |
| Optical / radio transports | Planned |

## Quick start

```bash
# From a clone
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Generate local node identity
dragon-gate status

# Inspect a URL (Redirect Observatory)
dragon-gate inspect https://example.com
dragon-gate trace https://example.com

# DNS / TLS labs
dragon-gate dns example.com
dragon-gate tls example.com

# Evidence
dragon-gate evidence verify path/to/events.ndjson
```

## Design principles

1. **Local autonomy first** — diagnostics and local services work without public internet.
2. **Explicit trust** — never trust a node merely because it responds.
3. **Evidence over assertion** — every observation produces structured, hashable evidence.
4. **Transport independence** — Ethernet, Wi-Fi, WireGuard, and future physical transports are pluggable.
5. **No silent privilege escalation** — ordinary inspection does not require root; privileged capabilities are declared and opt-in.
6. **Aurora owns destination routing** — Dragon Gate provides the operational, security, and diagnostic surface around it.

## Repository layout

```
src/dragon_gate/
  core/          # identity, config, health, registry, events
  network/       # topology, peers, routes, gateways, measurements
  transport/     # interface adapters, capability reporting
  web/           # Redirect Observatory, HTTP/TLS inspection
  security/      # authentication, policy, audit
  aurora/        # destination resolver + gateway adapters
  evidence/      # canonical event schema, hashing, replay
  cli/           # single `dragon gate` namespace
schemas/         # JSON schemas for events and contracts
tests/           # comprehensive host-side + synthetic fixtures
docs/            # architecture, threat model, roadmap, contracts
packaging/arch/  # PKGBUILD and service units
```

## Documentation

- [Architecture](docs/architecture.md)
- [Network Autonomy Roadmap](docs/autonomy-roadmap.md)
- [Threat Model](docs/threat-model.md)
- [CLI Reference](docs/cli.md)
- [Aurora Integration Contract](docs/aurora-contract.md)
- [Evidence Schema](docs/evidence.md)
- [Installation & Arch packaging](docs/install.md)

## License

MIT
