"""SQLite-backed persistent peer, route, and gateway state."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_MIGRATIONS = {
    1: """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS peers (
        node_id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        trust TEXT NOT NULL DEFAULT 'discovered',
        reachability TEXT NOT NULL DEFAULT 'unknown',
        last_seen REAL NOT NULL DEFAULT 0,
        last_heartbeat_seq INTEGER NOT NULL DEFAULT 0,
        capabilities TEXT NOT NULL DEFAULT '[]',
        services TEXT NOT NULL DEFAULT '[]',
        metadata TEXT NOT NULL DEFAULT '{}',
        signed_identity TEXT,
        observed_at REAL NOT NULL DEFAULT 0,
        ingested_at REAL NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS peer_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        event TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '{}',
        observed_at REAL NOT NULL,
        ingested_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS routes (
        destination TEXT PRIMARY KEY,
        next_hop TEXT NOT NULL,
        metric INTEGER NOT NULL DEFAULT 100,
        source TEXT NOT NULL DEFAULT 'manual',
        authorized INTEGER NOT NULL DEFAULT 0,
        metadata TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS gateways (
        gateway_id TEXT PRIMARY KEY,
        endpoint TEXT NOT NULL,
        authorized INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT 'unknown',
        last_check REAL NOT NULL DEFAULT 0,
        metadata TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS nonces (
        nonce TEXT PRIMARY KEY,
        created_at REAL NOT NULL
    );
    """,
}


class PeerStore:
    """Transactional SQLite store for peer runtime state."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def _migrate(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        current = int(row["value"]) if row else 0
        for ver in sorted(_MIGRATIONS):
            if ver > current:
                self._conn.executescript(_MIGRATIONS[ver])
                self._conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                    (str(ver),),
                )

    def close(self) -> None:
        self._conn.close()

    # --- peers ---

    def upsert_peer(self, peer: dict[str, Any]) -> None:
        now = time.time()
        self._conn.execute(
            """
            INSERT INTO peers(
                node_id, public_key, trust, reachability, last_seen,
                last_heartbeat_seq, capabilities, services, metadata,
                signed_identity, observed_at, ingested_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(node_id) DO UPDATE SET
                public_key=excluded.public_key,
                trust=excluded.trust,
                reachability=excluded.reachability,
                last_seen=excluded.last_seen,
                last_heartbeat_seq=excluded.last_heartbeat_seq,
                capabilities=excluded.capabilities,
                services=excluded.services,
                metadata=excluded.metadata,
                signed_identity=excluded.signed_identity,
                observed_at=excluded.observed_at,
                ingested_at=excluded.ingested_at
            """,
            (
                peer["node_id"],
                peer.get("public_key", ""),
                peer.get("trust", "discovered"),
                peer.get("reachability", "unknown"),
                peer.get("last_seen", now),
                peer.get("last_heartbeat_seq", 0),
                json.dumps(peer.get("capabilities", [])),
                json.dumps(peer.get("services", [])),
                json.dumps(peer.get("metadata", {})),
                json.dumps(peer.get("signed_identity")) if peer.get("signed_identity") else None,
                peer.get("observed_at", now),
                now,
            ),
        )

    def get_peer(self, node_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM peers WHERE node_id=?", (node_id,)
        ).fetchone()
        return self._peer_row(row) if row else None

    def list_peers(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM peers ORDER BY node_id").fetchall()
        return [self._peer_row(r) for r in rows]

    def set_trust(self, node_id: str, trust: str) -> None:
        self._conn.execute(
            "UPDATE peers SET trust=?, ingested_at=? WHERE node_id=?",
            (trust, time.time(), node_id),
        )

    def set_reachability(
        self, node_id: str, state: str, *,
        last_seen: float | None = None,
        seq: int | None = None,
    ) -> None:
        now = time.time()
        if seq is not None:
            self._conn.execute(
                """UPDATE peers SET reachability=?, last_seen=?, last_heartbeat_seq=?,
                   observed_at=?, ingested_at=? WHERE node_id=?""",
                (state, last_seen or now, seq, last_seen or now, now, node_id),
            )
        else:
            self._conn.execute(
                """UPDATE peers SET reachability=?, last_seen=?,
                   observed_at=?, ingested_at=? WHERE node_id=?""",
                (state, last_seen or now, last_seen or now, now, node_id),
            )

    def record_observation(
        self, node_id: str, event: str, detail: dict[str, Any] | None = None,
        observed_at: float | None = None,
    ) -> None:
        now = time.time()
        self._conn.execute(
            """INSERT INTO peer_observations(node_id, event, detail, observed_at, ingested_at)
               VALUES (?,?,?,?,?)""",
            (node_id, event, json.dumps(detail or {}), observed_at or now, now),
        )

    def _peer_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "node_id": row["node_id"],
            "public_key": row["public_key"],
            "trust": row["trust"],
            "reachability": row["reachability"],
            "last_seen": row["last_seen"],
            "last_heartbeat_seq": row["last_heartbeat_seq"],
            "capabilities": json.loads(row["capabilities"] or "[]"),
            "services": json.loads(row["services"] or "[]"),
            "metadata": json.loads(row["metadata"] or "{}"),
            "signed_identity": json.loads(row["signed_identity"])
            if row["signed_identity"]
            else None,
            "observed_at": row["observed_at"],
            "ingested_at": row["ingested_at"],
        }

    # --- nonce replay protection ---

    def seen_nonce(self, nonce: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM nonces WHERE nonce=?", (nonce,)
        ).fetchone()
        return row is not None

    def record_nonce(self, nonce: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO nonces(nonce, created_at) VALUES (?,?)",
            (nonce, time.time()),
        )
        # prune old nonces (>1h)
        cutoff = time.time() - 3600
        self._conn.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))

    # --- routes / gateways ---

    def list_routes(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM routes").fetchall()
        return [
            {
                "destination": r["destination"],
                "next_hop": r["next_hop"],
                "metric": r["metric"],
                "source": r["source"],
                "authorized": bool(r["authorized"]),
                "metadata": json.loads(r["metadata"] or "{}"),
            }
            for r in rows
        ]

    def list_gateways(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM gateways").fetchall()
        return [
            {
                "gateway_id": r["gateway_id"],
                "endpoint": r["endpoint"],
                "authorized": bool(r["authorized"]),
                "state": r["state"],
                "last_check": r["last_check"],
                "metadata": json.loads(r["metadata"] or "{}"),
            }
            for r in rows
        ]
