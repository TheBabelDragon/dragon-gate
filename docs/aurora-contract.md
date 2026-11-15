# Aurora Integration Contract

Aurora owns destination routing. Dragon Gate provides security, diagnostics, orchestration, and the operational interface.

## Adapter surface

```python
class AuroraAdapter(Protocol):
    def resolve_destination(self, target: str) -> AuroraRouteDiagnosis: ...
    def list_gateways(self) -> list[dict]: ...
    def health(self) -> dict: ...
```

## Rules

1. External egress remains **disabled by default**.
2. Do not duplicate Aurora’s routing engine.
3. Preserve Aurora’s authenticated gateway capability claims, sequence protections, cooldown behavior, and SSRF/deny_private policy.
4. Dragon Gate may:
   - Discover configured Aurora gateways
   - Query destination resolution
   - Inspect available routes
   - Report gateway health
   - Exchange authorized node/service metadata
   - Consume route diagnostics
   - Export network observations as evidence

## Reference endpoints (from Aurora swarm)

- `GET /comms/destinations/resolve?target=`
- `GET /comms/routes`
- `GET /comms/gateways`
- `GET /comms/network/status`
- `POST /comms/route_send` (mesh delivery; not automatic egress)

`RELAY_IMPLEMENTED = False` in current Aurora — Dragon Gate must not assume relay capability.
