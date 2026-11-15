# Trust and Enrollment

1. **Discover** — untrusted observation only.
2. **Authenticate** — mutual Ed25519 handshake with nonces.
3. **Authorize** — explicit operator action (`peer authorize`).
4. **Revoke** — explicit deny; session dropped.

Never auto-authorize on discovery or authentication.
