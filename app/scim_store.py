from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from threading import Lock
from typing import Any


class SCIMStore:
    def __init__(self, db_path: str = "agentguard_scim.db") -> None:
        self._db_path = db_path
        self._is_postgres = db_path.startswith("postgresql://")
        self._lock = Lock()

        retries = 3
        delay = 0.5
        last_exc: Exception | None = None
        for _ in range(retries):
            try:
                if self._is_postgres:
                    import psycopg
                    from psycopg.rows import dict_row

                    self._conn = psycopg.connect(db_path, row_factory=dict_row, autocommit=True)
                else:
                    self._conn = sqlite3.connect(db_path, check_same_thread=False)
                    self._conn.row_factory = sqlite3.Row
                break
            except Exception as exc:  # pragma: no cover
                last_exc = exc
                time.sleep(delay)
        else:  # pragma: no cover
            raise RuntimeError(f"Failed to connect SCIM store: {last_exc}")

        self._init_db()

    def _q(self, query: str) -> str:
        if self._is_postgres:
            return query.replace("?", "%s")
        return query

    def _fetchall(self, query: str, params: tuple[Any, ...] = ()) -> list[Any]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(self._q(query), params)
            return cur.fetchall()

    def _fetchone(self, query: str, params: tuple[Any, ...] = ()) -> Any | None:
        rows = self._fetchall(query, params)
        return rows[0] if rows else None

    def _execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(self._q(query), params)
            if not self._is_postgres:
                self._conn.commit()

    def _init_db(self) -> None:
        self._execute(
            """
            CREATE TABLE IF NOT EXISTS scim_users (
                user_name TEXT PRIMARY KEY,
                external_id TEXT,
                active INTEGER NOT NULL,
                display_name TEXT,
                email TEXT,
                access_role TEXT,
                access_tenant_id TEXT,
                raw_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        self._execute(
            "CREATE INDEX IF NOT EXISTS idx_scim_users_access ON scim_users(access_tenant_id, access_role)"
        )

    def upsert_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        user_name = str(payload.get("userName") or "").strip()
        if not user_name:
            raise ValueError("userName is required")

        active = 1 if payload.get("active", True) else 0
        display_name = payload.get("displayName")
        external_id = payload.get("externalId")
        emails = payload.get("emails") or []
        email = None
        if isinstance(emails, list) and emails:
            first = emails[0]
            if isinstance(first, dict):
                email = first.get("value")

        access = payload.get("urn:agentguard:access", {})
        if not isinstance(access, dict):
            access = {}
        role = access.get("role")
        tenant_id = access.get("tenant_id")

        now = datetime.now(timezone.utc).isoformat()
        existing = self._fetchone("SELECT user_name FROM scim_users WHERE user_name = ?", (user_name,))

        if existing:
            self._execute(
                """
                UPDATE scim_users
                SET external_id = ?, active = ?, display_name = ?, email = ?,
                    access_role = ?, access_tenant_id = ?, raw_json = ?, updated_at = ?
                WHERE user_name = ?
                """,
                (
                    external_id,
                    active,
                    display_name,
                    email,
                    role,
                    tenant_id,
                    json.dumps(payload),
                    now,
                    user_name,
                ),
            )
        else:
            self._execute(
                """
                INSERT INTO scim_users (
                    user_name, external_id, active, display_name, email,
                    access_role, access_tenant_id, raw_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_name,
                    external_id,
                    active,
                    display_name,
                    email,
                    role,
                    tenant_id,
                    json.dumps(payload),
                    now,
                ),
            )

        return self.get_user(user_name)

    def get_user(self, user_name: str) -> dict[str, Any]:
        row = self._fetchone(
            "SELECT raw_json FROM scim_users WHERE user_name = ?",
            (user_name,),
        )
        if not row:
            raise KeyError(f"SCIM user not found: {user_name}")
        return json.loads(row["raw_json"])

    def list_users(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._fetchall(
            "SELECT raw_json FROM scim_users ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        )
        return [json.loads(row["raw_json"]) for row in rows]

    def delete_user(self, user_name: str) -> None:
        self._execute("DELETE FROM scim_users WHERE user_name = ?", (user_name,))

    def resolve_access(self, principal_id: str) -> tuple[str | None, str | None]:
        row = self._fetchone(
            "SELECT access_role, access_tenant_id, active FROM scim_users WHERE user_name = ?",
            (principal_id,),
        )
        if not row:
            return None, None
        if int(row["active"]) != 1:
            return None, None
        return row["access_role"], row["access_tenant_id"]

    def ping(self) -> bool:
        try:
            row = self._fetchone("SELECT 1 AS ok")
            return bool(row and row["ok"] == 1)
        except Exception:
            return False

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
