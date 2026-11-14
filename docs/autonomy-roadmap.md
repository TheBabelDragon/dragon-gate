# Network Autonomy Roadmap

## Principle

Do not claim that a software overlay replaces physical connectivity.  
Build the infrastructure needed to progressively provide independent physical connectivity and shared upstream access.

## Layers

### A. Local network autonomy (v0.1 foundation)

- Local DNS resolution and service discovery (stubs + contracts)
- Local service hosting surface
- Peer-to-peer communication models
- Operation without public internet for diagnostics and identity
- Persistent node identities
- Local health reporting

### B. Multi-node connectivity (v0.2)

- Authenticated peer registration (done in v0.1)
- Reachability measurement
- Topology discovery
- Route advertisement and selection (models done)
- Link failure detection and failover (models done)

### C. Transport independence (v0.2–v0.3)

- Multiple physical interfaces
- Ethernet / Wi-Fi
- Optional cellular / tethered upstream
- WireGuard encrypted overlay (integration boundary in v0.1)
- Future optical and radio transports (c3-field-swarm, Signal Processor experiments)

### D. Upstream independence (v0.3+)

- Multiple independently configured gateways
- Gateway health and cooldown
- Policy-controlled upstream selection
- DNS resolver independence
- Local service availability during upstream outages
- Operation between Dragon Gate nodes without an ISP connection

### E. External connectivity (controlled)

- Optional authorized egress gateways
- Authenticated enrollment
- Explicit routing permissions
- No default open relay
- No automatic exposure of private services
