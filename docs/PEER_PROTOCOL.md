# Peer Protocol — DRAGON//GATE v0.3

## Overview

Transport-independent control protocol for mutual authentication, capability exchange, and heartbeats.

**Version:** 1  
**Framing:** 4-byte big-endian length + UTF-8 JSON body  
**Max message:** 64 KiB  
**Crypto:** Ed25519 (existing identity format)

## Handshake

```
Initiator                         Responder
   |--- HELLO (signed identity) --->|
   |<-- CHALLENGE (nonce) ----------|
   |--- RESPONSE (sign nonces) ---->|
   |<-- AUTH_OK (mutual sign) ------|
```

- Protocol version negotiated in HELLO.
- Nonces are single-use (persisted for replay protection).
- Invalid signature → AUTH_FAIL, connection closed.
- Success → peer stored as **AUTHENTICATED** (not AUTHORIZED).

## Trust states

| State | Meaning |
|-------|--------|
| DISCOVERED | Seen, not verified |
| AUTHENTICATED | Mutual crypto proof |
| AUTHORIZED | Explicit admin grant |
| REVOKED | Explicit deny |

**Authenticated ≠ authorized.**

## Heartbeat

- HEARTBEAT / HEARTBEAT_ACK with sequence numbers.
- REACHABLE → STALE after timeout → UNREACHABLE on disconnect.

## Non-goals

- Packet forwarding / relay
- Automatic egress
- Automatic authorization
