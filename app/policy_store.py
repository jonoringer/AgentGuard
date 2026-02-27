from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from .models import PolicyConfig, PolicyCurrentResponse, PolicyVersionSummary


class PolicyStore:
    def __init__(self, db_path: str = "agentguard_policy.db") -> None:
        self._db_path = db_path
        self._is_postgres = db_path.startswith("postgresql://")
        self._lock = Lock()

        if self._is_postgres:
            import psycopg
            from psycopg.rows import dict_row

            self._conn = psycopg.connect(db_path, row_factory=dict_row, autocommit=True)
        else:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row

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
            CREATE TABLE IF NOT EXISTS policy_versions (
                tenant_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                approved_by TEXT,
                PRIMARY KEY (tenant_id, version)
            )
            """
        )
        if self._is_postgres:
            row = self._fetchone(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'policy_versions' AND column_name = 'tenant_id'
                """
            )
            if not row:
                self._execute("ALTER TABLE policy_versions ADD COLUMN tenant_id TEXT DEFAULT 'global'")
        else:
            row = self._fetchone(
                "SELECT 1 FROM pragma_table_info('policy_versions') WHERE name = 'tenant_id'"
            )
            if not row:
                self._execute("ALTER TABLE policy_versions ADD COLUMN tenant_id TEXT DEFAULT 'global'")

        self._execute(
            "CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant_status ON policy_versions(tenant_id, status, version DESC)"
        )

    def ensure_seed(self, policy: PolicyConfig, tenant_id: str = "global", actor: str = "system") -> None:
        row = self._fetchone(
            "SELECT COUNT(*) AS c FROM policy_versions WHERE tenant_id = ?",
            (tenant_id,),
        )
        count = row["c"] if row else 0
        if count > 0:
            return

        now = datetime.now(timezone.utc).isoformat()
        self._execute(
            """
            INSERT INTO policy_versions (tenant_id, version, status, policy_json, created_at, created_by, approved_by)
            VALUES (?, 1, 'approved', ?, ?, ?, ?)
            """,
            (tenant_id, policy.model_dump_json(), now, actor, actor),
        )

    def get_current(self, tenant_id: str) -> PolicyCurrentResponse:
        row = self._fetchone(
            """
            SELECT tenant_id, version, status, policy_json, created_at, created_by, approved_by
            FROM policy_versions
            WHERE tenant_id = ? AND status = 'approved'
            ORDER BY version DESC
            LIMIT 1
            """,
            (tenant_id,),
        )

        if not row:
            raise RuntimeError(f"No approved policy version found for tenant '{tenant_id}'")

        return PolicyCurrentResponse(
            tenant_id=row["tenant_id"],
            version=row["version"],
            status=row["status"],
            policy=PolicyConfig.model_validate(json.loads(row["policy_json"])),
            created_at=datetime.fromisoformat(row["created_at"]),
            created_by=row["created_by"],
            approved_by=row["approved_by"],
        )

    def list_versions(self, tenant_id: str, limit: int = 100) -> list[PolicyVersionSummary]:
        rows = self._fetchall(
            """
            SELECT tenant_id, version, status, created_at, created_by, approved_by
            FROM policy_versions
            WHERE tenant_id = ?
            ORDER BY version DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        )

        return [
            PolicyVersionSummary(
                tenant_id=row["tenant_id"],
                version=row["version"],
                status=row["status"],
                created_at=datetime.fromisoformat(row["created_at"]),
                created_by=row["created_by"],
                approved_by=row["approved_by"],
            )
            for row in rows
        ]

    def propose(self, tenant_id: str, policy: PolicyConfig, actor: str) -> PolicyVersionSummary:
        row = self._fetchone(
            "SELECT COALESCE(MAX(version), 0) AS v FROM policy_versions WHERE tenant_id = ?",
            (tenant_id,),
        )
        next_version = (row["v"] if row else 0) + 1
        now = datetime.now(timezone.utc).isoformat()

        self._execute(
            """
            INSERT INTO policy_versions (tenant_id, version, status, policy_json, created_at, created_by, approved_by)
            VALUES (?, ?, 'proposed', ?, ?, ?, NULL)
            """,
            (tenant_id, next_version, policy.model_dump_json(), now, actor),
        )

        return PolicyVersionSummary(
            tenant_id=tenant_id,
            version=next_version,
            status="proposed",
            created_at=datetime.fromisoformat(now),
            created_by=actor,
            approved_by=None,
        )

    def approve(self, tenant_id: str, version: int, actor: str) -> PolicyCurrentResponse:
        row = self._fetchone(
            "SELECT version FROM policy_versions WHERE tenant_id = ? AND version = ?",
            (tenant_id, version),
        )
        if not row:
            raise ValueError(f"Policy version {version} not found for tenant '{tenant_id}'")

        self._execute(
            "UPDATE policy_versions SET status = 'archived' WHERE tenant_id = ? AND status = 'approved'",
            (tenant_id,),
        )
        self._execute(
            "UPDATE policy_versions SET status = 'approved', approved_by = ? WHERE tenant_id = ? AND version = ?",
            (actor, tenant_id, version),
        )
        return self.get_current(tenant_id=tenant_id)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
