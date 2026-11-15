# Threat Model — DRAGON//GATE v0.2

## Assets

- Node private keys
- Signed identity records
- Evidence logs (integrity)
- Gateway authorization state
- Configuration

## Adversaries

- Network observer / MITM
- Malicious peer claiming false identity
- SSRF attacker via redirect or DNS rebinding
- Compromised upstream gateway
- Local privilege escalation attempts

## Mitigations

| Threat | Mitigation |
|--------|------------|
| Spoofed peer | Ed25519 signed identity required for enrollment |
| SSRF via redirect | Per-hop URL + DNS + connection pinning |
| DNS rebinding | Validate entire answer set; connect only to validated literals; no second DNS |
| Mixed public/private DNS | Reject entire resolution |
| HTTPS downgrade | Detected and refused under FOLLOW_SAFE |
| Cert bypass | Certificate verification never disabled; SNI uses original hostname |
| Open relay | Egress disabled by default |
| Evidence tampering | SHA-256 content hashes |
| Credential leakage in logs | URL redaction; header filtering |

## Explicit non-goals

- Full mesh encryption (WireGuard boundary only)
- Replacement of physical last-mile connectivity
- Automatic trust of discovered nodes
