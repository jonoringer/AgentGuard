from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from threading import Lock
from typing import Any, AsyncGenerator
from uuid import uuid4

from .models import AuditRecord, Decision


class AuditStore:
    def __init__(self, db_path: str = "agentguard_audit.db") -> None:
        self._db_path = db_path
        self._is_postgres = db_path.startswith("postgresql://")
        self._lock = Lock()
        self._subscribers: set[asyncio.Queue[AuditRecord]] = set()

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
            raise RuntimeError(f"Failed to connect audit store: {last_exc}")

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

    def _execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(self._q(query), params)
            if not self._is_postgres:
                self._conn.commit()

    def _init_db(self) -> None:
        self._execute(
            """
            CREATE TABLE IF NOT EXISTS audits (
                audit_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                enforcement_action TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence REAL NOT NULL,
                record_json TEXT NOT NULL
            )
            """
        )
        if self._is_postgres:
            row = self._fetchall(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'audits' AND column_name = 'tenant_id'
                """
            )
            if not row:
                self._execute("ALTER TABLE audits ADD COLUMN tenant_id TEXT DEFAULT 'global'")
        else:
            row = self._fetchall("SELECT 1 FROM pragma_table_info('audits') WHERE name = 'tenant_id'")
            if not row:
                self._execute("ALTER TABLE audits ADD COLUMN tenant_id TEXT DEFAULT 'global'")
        self._execute(
            "CREATE INDEX IF NOT EXISTS idx_audits_tenant_agent_created_at ON audits(tenant_id, agent_id, created_at DESC)"
        )
        self._execute(
            "CREATE INDEX IF NOT EXISTS idx_audits_tenant_decision_created_at ON audits(tenant_id, decision, created_at DESC)"
        )

    def append(self, record: AuditRecord) -> None:
        tenant_id = record.action.tenant_id or "global"
        self._execute(
            """
            INSERT INTO audits (
                audit_id, created_at, tenant_id, agent_id, decision, enforcement_action,
                risk_score, confidence, record_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.audit_id,
                record.created_at.isoformat(),
                tenant_id,
                record.action.agent_id,
                record.decision.value,
                record.enforcement_action.value,
                record.risk_score,
                record.confidence,
                record.model_dump_json(),
            ),
        )
        for queue in tuple(self._subscribers):
            queue.put_nowait(record)

    def new_audit_id(self) -> str:
        return str(uuid4())

    def query(
        self,
        agent_id: str | None = None,
        decision: Decision | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[AuditRecord]:
        clauses: list[str] = []
        params: list[str | int] = []

        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if decision:
            clauses.append("decision = ?")
            params.append(decision.value)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._fetchall(
            f"""
            SELECT record_json
            FROM audits
            {where_sql}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (*params, limit),
        )
        return [AuditRecord.model_validate(json.loads(row["record_json"])) for row in rows]

    async def stream(self) -> AsyncGenerator[AuditRecord, None]:
        queue: asyncio.Queue[AuditRecord] = asyncio.Queue()
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)

    def ping(self) -> bool:
        try:
            rows = self._fetchall("SELECT 1 AS ok")
            return bool(rows and rows[0]["ok"] == 1)
        except Exception:
            return False

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
