# Peer Runtime — DRAGON//GATE v0.3

## Components

| Module | Role |
|--------|------|
| `runtime/store.py` | SQLite peers, nonces, routes, gateways |
| `runtime/protocol.py` | Messages, handshake helpers |
| `runtime/transport.py` | Framed TCP |
| `runtime/node.py` | `NodeRuntime` |

## Defaults

- Bind: `127.0.0.1` (local-only)
- No open relay
- No automatic gateway egress
- Data dir: `$XDG_DATA_HOME/dragon-gate` or configured path

## Lifecycle

```python
rt = NodeRuntime(data_dir=..., bind_host="127.0.0.1", bind_port=0)
host, port = await rt.start()
await rt.connect_peer("127.0.0.1", other_port)
rt.authorize_peer(peer_id)  # explicit
snap = rt.topology_snapshot()
await rt.stop()
```

## Persistence

WAL SQLite. Identity file mode `0600`. Schema migrations via `meta.schema_version`.
