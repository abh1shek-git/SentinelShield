"""Small SQLite store with idempotent alerts and simulated expiring blocks."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import sqlite3
from typing import Any, Iterator

from sentinelshield.detection.rules import DetectionResult
from sentinelshield.processing.traffic import TrafficWindowFeatures


SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic_windows (
    id INTEGER PRIMARY KEY,
    window_start REAL NOT NULL,
    window_seconds REAL NOT NULL CHECK (window_seconds > 0),
    source_kind TEXT NOT NULL,
    features_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (window_start, window_seconds, source_kind)
);

CREATE TABLE IF NOT EXISTS detection_events (
    event_key TEXT PRIMARY KEY,
    traffic_window_id INTEGER NOT NULL REFERENCES traffic_windows(id),
    window_start REAL NOT NULL,
    label TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detection_events_created_at
    ON detection_events(created_at);

CREATE TABLE IF NOT EXISTS mitigation_events (
    id INTEGER PRIMARY KEY,
    event_key TEXT REFERENCES detection_events(event_key) ON DELETE SET NULL,
    target_ip TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action = 'temporary_block'),
    mode TEXT NOT NULL CHECK (mode = 'simulation'),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mitigation_events_expiry
    ON mitigation_events(expires_at);
"""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime | None = None) -> str:
    moment = value or _utc_now()
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


class SQLiteStore:
    """Persist aggregate windows, deduplicated alerts, and simulation-only blocks."""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.database_path), timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create tables and indexes if this is a new database."""
        with self._connection() as connection:
            connection.executescript(SCHEMA)

    @staticmethod
    def _insert_window(
        connection: sqlite3.Connection, features: TrafficWindowFeatures
    ) -> tuple[int, bool]:
        cursor = connection.execute(
            """INSERT OR IGNORE INTO traffic_windows
               (window_start, window_seconds, source_kind, features_json, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                features.window_start,
                features.window_seconds,
                features.source_kind,
                json.dumps(asdict(features), sort_keys=True, allow_nan=False),
                _timestamp(),
            ),
        )
        row = connection.execute(
            """SELECT id FROM traffic_windows
               WHERE window_start = ? AND window_seconds = ? AND source_kind = ?""",
            (features.window_start, features.window_seconds, features.source_kind),
        ).fetchone()
        if row is None:
            raise RuntimeError("traffic window insert did not produce a row")
        return int(row["id"]), cursor.rowcount == 1

    def record_window(self, features: TrafficWindowFeatures) -> bool:
        """Store one window once; return false when the same window was already stored."""
        with self._connection() as connection:
            _, inserted = self._insert_window(connection, features)
            return inserted

    def record_detection(
        self, features: TrafficWindowFeatures, result: DetectionResult
    ) -> bool:
        """Persist an alert once; normal windows are not inserted as alert events."""
        if not result.is_alert:
            return False
        with self._connection() as connection:
            traffic_window_id, _ = self._insert_window(connection, features)
            event_payload = json.dumps(
                {
                    "window_start": features.window_start,
                    "window_seconds": features.window_seconds,
                    "source_kind": features.source_kind,
                    "label": result.label,
                    "reasons": result.reasons,
                },
                sort_keys=True,
                allow_nan=False,
            )
            event_key = hashlib.sha256(event_payload.encode("utf-8")).hexdigest()
            cursor = connection.execute(
                """INSERT OR IGNORE INTO detection_events
                   (event_key, traffic_window_id, window_start, label, reasons_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    event_key,
                    traffic_window_id,
                    features.window_start,
                    result.label,
                    json.dumps(result.reasons),
                    _timestamp(),
                ),
            )
            return cursor.rowcount == 1

    def list_traffic_windows(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent stored window feature records, newest first."""
        if limit < 1:
            raise ValueError("limit must be at least one")
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT id, window_start, window_seconds, source_kind,
                          features_json, created_at
                   FROM traffic_windows ORDER BY window_start DESC, id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "window_start": row["window_start"],
                "window_seconds": row["window_seconds"],
                "source_kind": row["source_kind"],
                "features": json.loads(row["features_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def list_detection_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent alert records, newest first."""
        if limit < 1:
            raise ValueError("limit must be at least one")
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT event_key, traffic_window_id, window_start, label,
                          reasons_json, created_at
                   FROM detection_events ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                "event_key": row["event_key"],
                "traffic_window_id": row["traffic_window_id"],
                "window_start": row["window_start"],
                "label": row["label"],
                "reasons": json.loads(row["reasons_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def record_simulated_block(
        self,
        target_ip: str,
        *,
        reason: str,
        ttl_seconds: float = 300.0,
        event_key: str | None = None,
        created_at: datetime | None = None,
    ) -> int:
        """Record a temporary simulation entry; this method never changes a firewall."""
        try:
            normalized_ip = str(ipaddress.ip_address(target_ip))
        except ValueError as error:
            raise ValueError("target_ip must be a valid IPv4 or IPv6 address") from error
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        if not reason.strip():
            raise ValueError("reason cannot be empty")

        created = created_at or _utc_now()
        created_iso = _timestamp(created)
        expires_iso = _timestamp(created + timedelta(seconds=ttl_seconds))
        with self._connection() as connection:
            cursor = connection.execute(
                """INSERT INTO mitigation_events
                   (event_key, target_ip, action, mode, reason, created_at, expires_at)
                   VALUES (?, ?, 'temporary_block', 'simulation', ?, ?, ?)""",
                (event_key, normalized_ip, reason.strip(), created_iso, expires_iso),
            )
            return int(cursor.lastrowid)

    def active_simulated_blocks(
        self, *, as_of: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Return simulation entries that have not expired at the supplied UTC time."""
        now = _timestamp(as_of)
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT id, event_key, target_ip, action, mode, reason,
                          created_at, expires_at
                   FROM mitigation_events WHERE expires_at > ?
                   ORDER BY created_at DESC""",
                (now,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_mitigation_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recorded mitigation decisions, including expired simulations."""
        if limit < 1:
            raise ValueError("limit must be at least one")
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT id, event_key, target_ip, action, mode, reason,
                          created_at, expires_at
                   FROM mitigation_events ORDER BY created_at DESC, id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
