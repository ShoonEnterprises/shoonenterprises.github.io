"""Quota enforcement: scarcity model for the free sandbox.

- wallet/API-key identity required; ≤10 tasks/day/identity
- ≤20 tasks/day/service globally (the scarcity model)
- global daily simulated token budget with auto-pause on breach
- kill switch as a feature flag (no auto-resume ever)

Persistence: all counters and the pause state live in SQLite
(data/quotas.db), so a restart no longer resets daily usage. Counters are
keyed by UTC date; rows older than 7 days are pruned on startup.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

from catalog import SERVICES

SERVICE_SLOT_CAPS = {s["id"]: s["daily_free_slots"] for s in SERVICES}
PER_IDENTITY_DAILY_CAP = 10
PRUNE_AFTER_DAYS = 7


class QuotaManager:
    def __init__(self, daily_token_budget: int, admin_token: str, db_path: Path) -> None:
        self._lock = threading.Lock()
        self._db_path = db_path
        self.daily_token_budget = daily_token_budget
        self.admin_token = admin_token
        self._init_db()

    # ------------------------------------------------------------ storage
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS daily_counters(
                       day TEXT NOT NULL,
                       kind TEXT NOT NULL,
                       key TEXT NOT NULL,
                       count INTEGER NOT NULL DEFAULT 0,
                       PRIMARY KEY (day, kind, key))"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS daily_tokens(
                       day TEXT PRIMARY KEY,
                       tokens INTEGER NOT NULL DEFAULT 0)"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS state(
                       key TEXT PRIMARY KEY,
                       value TEXT NOT NULL)"""
            )
            cutoff = (
                dt.datetime.now(dt.timezone.utc).date()
                - dt.timedelta(days=PRUNE_AFTER_DAYS)
            ).isoformat()
            conn.execute("DELETE FROM daily_counters WHERE day < ?", (cutoff,))
            conn.execute("DELETE FROM daily_tokens WHERE day < ?", (cutoff,))

    @staticmethod
    def _today() -> str:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()

    def _get_counter(self, conn: sqlite3.Connection, kind: str, key: str) -> int:
        row = conn.execute(
            "SELECT count FROM daily_counters WHERE day=? AND kind=? AND key=?",
            (self._today(), kind, key),
        ).fetchone()
        return row[0] if row else 0

    def _bump_counter(
        self, conn: sqlite3.Connection, kind: str, key: str, delta: int = 1
    ) -> int:
        day = self._today()
        conn.execute(
            """INSERT INTO daily_counters(day, kind, key, count)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(day, kind, key)
               DO UPDATE SET count = count + ?""",
            (day, kind, key, delta, delta),
        )
        row = conn.execute(
            "SELECT count FROM daily_counters WHERE day=? AND kind=? AND key=?",
            (day, kind, key),
        ).fetchone()
        return row[0]

    def _get_tokens(self, conn: sqlite3.Connection) -> int:
        row = conn.execute(
            "SELECT tokens FROM daily_tokens WHERE day=?", (self._today(),)
        ).fetchone()
        return row[0] if row else 0

    def _add_tokens(self, conn: sqlite3.Connection, delta: int) -> None:
        day = self._today()
        conn.execute(
            """INSERT INTO daily_tokens(day, tokens) VALUES (?, ?)
               ON CONFLICT(day) DO UPDATE SET tokens = tokens + ?""",
            (day, delta, delta),
        )

    def _get_state(self, conn: sqlite3.Connection, key: str) -> Optional[str]:
        row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _set_state(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO state(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ------------------------------------------------------------ public API
    @property
    def paused(self) -> bool:
        with self._lock, self._connect() as conn:
            return self._get_state(conn, "paused") == "1"

    @property
    def pause_reason(self) -> Optional[str]:
        with self._lock, self._connect() as conn:
            return self._get_state(conn, "pause_reason")

    def slots_remaining(self, service_id: str) -> int:
        with self._lock, self._connect() as conn:
            cap = SERVICE_SLOT_CAPS.get(service_id, 0)
            used = self._get_counter(conn, "service", service_id)
            return max(0, cap - used)

    def check_and_consume(
        self, identity: str, service_id: str, est_tokens: int
    ) -> Tuple[bool, str]:
        with self._lock, self._connect() as conn:
            if self._get_state(conn, "paused") == "1":
                reason = self._get_state(conn, "pause_reason") or "paused"
                return False, f"intake paused: {reason}"
            used_identity = self._get_counter(conn, "identity", identity)
            if used_identity >= PER_IDENTITY_DAILY_CAP:
                return False, f"identity daily cap reached ({PER_IDENTITY_DAILY_CAP}/day)"
            used_service = self._get_counter(conn, "service", service_id)
            cap = SERVICE_SLOT_CAPS.get(service_id, 20)
            if used_service >= cap:
                return False, f"service daily free slots exhausted ({cap}/day)"
            tokens_today = self._get_tokens(conn)
            if tokens_today + est_tokens > self.daily_token_budget:
                self._set_state(conn, "paused", "1")
                self._set_state(
                    conn, "pause_reason", "global daily token budget breached (auto-pause)"
                )
                return False, "global daily token budget breached — auto-paused"
            self._bump_counter(conn, "identity", identity)
            self._bump_counter(conn, "service", service_id)
            self._add_tokens(conn, est_tokens)
            return True, "ok"

    def record_origin(self, origin: str) -> None:
        """Count one accepted task by traffic origin: human | machine | mcp."""
        with self._lock, self._connect() as conn:
            self._bump_counter(conn, "origin", origin)

    def set_paused(self, paused: bool, reason: str) -> None:
        with self._lock, self._connect() as conn:
            self._set_state(conn, "paused", "1" if paused else "0")
            if paused:
                self._set_state(conn, "pause_reason", reason)
            else:
                conn.execute("DELETE FROM state WHERE key='pause_reason'")

    def usage_snapshot(self) -> Dict[str, object]:
        with self._lock, self._connect() as conn:
            day = self._today()
            per_identity: Dict[str, int] = {}
            per_service: Dict[str, int] = {}
            per_origin: Dict[str, int] = {}
            for kind, key, count in conn.execute(
                "SELECT kind, key, count FROM daily_counters WHERE day=?", (day,)
            ):
                if kind == "identity":
                    per_identity[key] = count
                elif kind == "service":
                    per_service[key] = count
                elif kind == "origin":
                    per_origin[key] = count
            return {
                "date": day,
                "paused": self._get_state(conn, "paused") == "1",
                "pause_reason": self._get_state(conn, "pause_reason"),
                "tokens_today": self._get_tokens(conn),
                "token_budget": self.daily_token_budget,
                "per_identity": per_identity,
                "per_service": per_service,
                "per_origin": per_origin,
            }
