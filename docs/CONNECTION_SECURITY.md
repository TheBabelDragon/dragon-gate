# Connection Security — DRAGON//GATE v0.2

## Central invariant

> A destination is not trusted because its hostname was validated.  
> It is trusted only when the actual connection is demonstrably bound to an authorized, validated destination.

URL-level SSRF checks are necessary but **not sufficient**. Dragon Gate enforces the boundary at the socket.

## Lifecycle

```
URL parse → scheme/host checks
    → fresh DNS resolution (no app-level cache)
    → validate ENTIRE address set (fail closed)
    → TCP connect to validated literal IP only
    → TLS wrap with server_hostname = original hostname (SNI + cert verify)
    → HTTP Host: original hostname
```

There is **no** second uncontrolled DNS lookup between validation and connect.

## Address policy

**Always blocked** (even with `allow_private`):

- Loopback (IPv4/IPv6)
- Link-local
- Multicast
- Unspecified / reserved
- Metadata service addresses and hostnames
- Scoped (zone-index) addresses
- IPv4-mapped IPv6 forms of the above

**Private (RFC1918 / ULA)** — blocked by default; optional `allow_private` permits only these classes.

**Mixed answers** — if any address in a DNS response is prohibited, or public and private are mixed, the **entire** resolution is rejected.

## Redirect chains

Every hop independently repeats the full lifecycle. Prior hop validation is never reused.

- `INSPECT_ONLY` — observe first response; do not follow
- `FOLLOW_SAFE` — follow after per-hop validation; refuse HTTPS→HTTP downgrade
- `SIMULATE` — follow for analysis; still records downgrade detection

`max_redirects = N` permits at most N redirect transitions; the final destination is still validated.

## TLS

Certificate verification is **never** disabled. When connecting to a literal IP, SNI and certificate hostname verification still use the original hostname.

## Evidence events

| Type | Meaning |
|------|--------|
| `web.redirect.inspect_started` | Inspection began |
| `web.redirect.hop_observed` | Hop response recorded |
| `security.ssrf.blocked` | Destination rejected |
| `security.redirect.downgrade_blocked` | HTTPS→HTTP refused |
| `security.redirect.loop_detected` | Loop |
| `security.redirect.limit_exceeded` | Depth limit |
| `security.dns.rebinding_detected` | Rebinding-class answer |
| `security.connection.destination_validated` | Socket bound to validated IP |

Sensitive data (credentials, cookies, bodies, private keys) is not persisted in evidence.

## Known limitations

- Application does not control OS-level DNS cache of the system resolver; we disable app-level caching and re-resolve per hop.
- Happy-Eyeballs / multipath is sequential over validated addresses only.
- Async path currently wraps the sync client via executor; aiohttp custom resolver remains a future option with equivalent guarantees.
