# CLI Reference

```
dragon-gate status [--json] [--check-internet]
dragon-gate doctor [--json]
dragon-gate inspect URL [--policy INSPECT_ONLY|FOLLOW_SAFE|SIMULATE] [--json] [--allow-private]
dragon-gate trace URL [--json] [--allow-private]
dragon-gate dns NAME [--json]
dragon-gate tls HOST [--port 443] [--json]
dragon-gate peers [--json]
dragon-gate routes [--json]
dragon-gate gateways [--json]
dragon-gate evidence verify PATH [--json]
dragon-gate evidence replay PATH [--json]
dragon-gate config validate [--json]
dragon-gate lab launch [name]
```

Exit codes:

- `0` success
- `1` validation / verification failure
- `2` network / protocol observation error
