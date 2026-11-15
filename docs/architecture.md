# Architecture — DRAGON//GATE v0.1

## Overview

Dragon Gate is a modular network operating environment. Subsystems are independently testable and communicate through explicit contracts and evidence events.

```
┌─────────────────────────────────────────────────────────┐
│                        CLI / Dashboard                   │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ gate-web │gate-net  │gate-sec  │gate-trans│ gate-aurora │
│ Redirect │ Peers    │ Policy   │ Caps     │ Adapter     │
│ DNS/TLS  │ Routes   │ SSRF     │ WireGuard│ Contracts   │
│          │ Gateways │ Auth     │          │             │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│                     gate-core                            │
│         identity · config · registry · health            │
├─────────────────────────────────────────────────────────┤
│                    gate-evidence                         │
│         canonical events · SHA-256 · NDJSON · replay     │
└─────────────────────────────────────────────────────────┘
```

## Subsystems

| Package | Responsibility |
|---------|----------------|
| `core` | Node identity (Ed25519), config, capability registry, health |
| `network` | Peers, routes, gateways, topology view |
| `transport` | Interface/capability reporting; WireGuard boundary |
| `web` | Redirect Observatory, DNS Lab, TLS Lab |
| `security` | Policy evaluation, SSRF protections |
| `aurora` | Destination routing adapter (Aurora owns the engine) |
| `evidence` | Canonical event schema, hashing, verification, replay |

## Trust model

- Every node has a stable `node_id` and Ed25519 key pair.
- Peer enrollment requires a verifiable signed identity record.
- Discovery ≠ authentication ≠ authorization.
- Gateways are never open relays by default; egress is opt-in and authorized.

## Evidence

Every observation emits an `EvidenceEvent` with separate source and ingest timestamps, content hash, and provenance. See [evidence.md](evidence.md).
