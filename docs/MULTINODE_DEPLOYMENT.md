# Multi-Node Deployment

## Local two-node lab

```bash
# Node A
dragon-gate node status  # uses local data dir

# Programmatic (v0.3 runtime)
# start two NodeRuntime instances on 127.0.0.1 with distinct data_dir
```

## Heterogeneous / offline

- Protocol is transport-independent; TCP is the first carrier.
- Future: WireGuard, Ethernet, optical, radio — same handshake.
- No mandatory internet or cloud dependency.

## Exposure

- Default bind `127.0.0.1`.
- Binding `0.0.0.0` is an explicit operator choice.
- Still not a packet relay.
