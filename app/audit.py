from __future__ import annotations

import asyncio
import json
import sqlite3
from threading import Lock
from typing import AsyncGenerator
from uuid import uuid4

from .models import AuditRecord, Decision


class AuditStore:
    def __init__(self, db_path: str = "agentguard_audit.db") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = Lock()
        self._subscribers: set[asyncio.Queue[AuditRecord]] = set()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audits (
                    audit_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    enforcement_action TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    record_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audits_agent_id_created_at ON audits(agent_id, created_at DESC)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audits_decision_created_at ON audits(decision, created_at DESC)"
            )
            self._conn.commit()

    def append(self, record: AuditRecord) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audits (
                    audit_id, created_at, agent_id, decision, enforcement_action,
                    risk_score, confidence, record_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.audit_id,
                    record.created_at.isoformat(),
                    record.action.agent_id,
                    record.decision.value,
                    record.enforcement_action.value,
                    record.risk_score,
                    record.confidence,
                    record.model_dump_json(),
                ),
            )
            self._conn.commit()
        for queue in tuple(self._subscribers):
            queue.put_nowait(record)

    def new_audit_id(self) -> str:
        return str(uuid4())

    def query(self, agent_id: str | None = None, decision: Decision | None = None, limit: int = 100) -> list[AuditRecord]:
        clauses: list[str] = []
        params: list[str | int] = []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if decision:
            clauses.append("decision = ?")
            params.append(decision.value)

        where_sql = ""
        if clauses:
            where_sql = "WHERE " + " AND ".join(clauses)

        with self._lock:
            cursor = self._conn.execute(
                f"""
                SELECT record_json
                FROM audits
                {where_sql}
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (*params, limit),
            )
            rows = cursor.fetchall()

        return [AuditRecord.model_validate(json.loads(row["record_json"])) for row in rows]

    async def stream(self) -> AsyncGenerator[AuditRecord, None]:
        queue: asyncio.Queue[AuditRecord] = asyncio.Queue()
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)
