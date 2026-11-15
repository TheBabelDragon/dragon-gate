# Threat Model — DRAGON//GATE v0.1

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

## Mitigations (v0.1)

| Threat | Mitigation |
|--------|------------|
| Spoofed peer | Ed25519 signed identity required for enrollment |
| Replay of enrollment | Signature over canonical record; future nonces planned |
| SSRF via redirect | Block loopback/private/link-local/metadata; re-validate after DNS |
| HTTPS downgrade | Detected and refused under FOLLOW_SAFE |
| Cert bypass | Certificate verification never disabled as convenience |
| Open relay | Egress disabled by default; explicit authorization required |
| Evidence tampering | SHA-256 content hashes; verify-before-trust |
| Root required for diagnostics | Ordinary inspect/dns/tls run unprivileged |

## Explicit non-goals (v0.1)

- Full mesh encryption mesh (WireGuard boundary only)
- Replacement of physical last-mile connectivity
- Automatic trust of discovered nodes
