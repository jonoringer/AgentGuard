from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from threading import Lock

from .models import PolicyConfig, PolicyCurrentResponse, PolicyVersionSummary


class PolicyStore:
    def __init__(self, db_path: str = "agentguard_policy.db") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_versions (
                    version INTEGER PRIMARY KEY,
                    status TEXT NOT NULL,
                    policy_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    approved_by TEXT
                )
                """
            )
            self._conn.commit()

    def ensure_seed(self, policy: PolicyConfig, actor: str = "system") -> None:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM policy_versions").fetchone()
            if row and row["c"] > 0:
                return
            now = datetime.now(timezone.utc).isoformat()
            self._conn.execute(
                """
                INSERT INTO policy_versions (version, status, policy_json, created_at, created_by, approved_by)
                VALUES (1, 'approved', ?, ?, ?, ?)
                """,
                (policy.model_dump_json(), now, actor, actor),
            )
            self._conn.commit()

    def get_current(self) -> PolicyCurrentResponse:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT version, status, policy_json, created_at, created_by, approved_by
                FROM policy_versions
                WHERE status = 'approved'
                ORDER BY version DESC
                LIMIT 1
                """
            ).fetchone()

        if not row:
            raise RuntimeError("No approved policy version found")

        return PolicyCurrentResponse(
            version=row["version"],
            status=row["status"],
            policy=PolicyConfig.model_validate(json.loads(row["policy_json"])),
            created_at=datetime.fromisoformat(row["created_at"]),
            created_by=row["created_by"],
            approved_by=row["approved_by"],
        )

    def list_versions(self, limit: int = 100) -> list[PolicyVersionSummary]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT version, status, created_at, created_by, approved_by
                FROM policy_versions
                ORDER BY version DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            PolicyVersionSummary(
                version=row["version"],
                status=row["status"],
                created_at=datetime.fromisoformat(row["created_at"]),
                created_by=row["created_by"],
                approved_by=row["approved_by"],
            )
            for row in rows
        ]

    def propose(self, policy: PolicyConfig, actor: str) -> PolicyVersionSummary:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM policy_versions").fetchone()
            next_version = (row["v"] if row else 0) + 1
            self._conn.execute(
                """
                INSERT INTO policy_versions (version, status, policy_json, created_at, created_by, approved_by)
                VALUES (?, 'proposed', ?, ?, ?, NULL)
                """,
                (next_version, policy.model_dump_json(), now, actor),
            )
            self._conn.commit()

        return PolicyVersionSummary(
            version=next_version,
            status="proposed",
            created_at=datetime.fromisoformat(now),
            created_by=actor,
            approved_by=None,
        )

    def approve(self, version: int, actor: str) -> PolicyCurrentResponse:
        with self._lock:
            row = self._conn.execute(
                "SELECT version, policy_json, created_at, created_by FROM policy_versions WHERE version = ?",
                (version,),
            ).fetchone()
            if not row:
                raise ValueError(f"Policy version {version} not found")

            self._conn.execute(
                "UPDATE policy_versions SET status = 'archived' WHERE status = 'approved'"
            )
            self._conn.execute(
                "UPDATE policy_versions SET status = 'approved', approved_by = ? WHERE version = ?",
                (actor, version),
            )
            self._conn.commit()

            approved = self._conn.execute(
                """
                SELECT version, status, policy_json, created_at, created_by, approved_by
                FROM policy_versions
                WHERE version = ?
                """,
                (version,),
            ).fetchone()

        return PolicyCurrentResponse(
            version=approved["version"],
            status=approved["status"],
            policy=PolicyConfig.model_validate(json.loads(approved["policy_json"])),
            created_at=datetime.fromisoformat(approved["created_at"]),
            created_by=approved["created_by"],
            approved_by=approved["approved_by"],
        )
