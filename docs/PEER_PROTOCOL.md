# Peer Protocol — DRAGON//GATE v0.3.1

## Handshake transcript

Both sides sign a canonical transcript binding:

- protocol_version
- initiator/responder node_id and public keys
- both nonces
- capability lists

AUTH_OK must carry a **signed identity** matching `node_id` / `public_key` fields (anti-substitution).

## Session integrity

After AUTH_OK, messages use **HKDF-SHA256** directional keys and **HMAC-SHA256** MACs with strict per-direction sequence numbers. Replay and reordering are rejected. Sessions expire (default 1h).

## Revocation

REVOKED peers are refused at handshake on both sides. Active sessions are closed on revoke. Reconnect does **not** restore trust; explicit `reenroll_clear_revocation` is required before re-auth can elevate again.

## Challenges

Nonces are claimed in SQLite with TTL (default 120s). Reuse is rejected.

## Non-goals

No packet relay, no auto-egress, authenticated ≠ authorized.
