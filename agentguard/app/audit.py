from __future__ import annotations

import asyncio
from collections import deque
from typing import AsyncGenerator
from uuid import uuid4

from .models import AuditRecord, Decision


class AuditStore:
    def __init__(self, max_records: int = 10_000) -> None:
        self._records: deque[AuditRecord] = deque(maxlen=max_records)
        self._subscribers: set[asyncio.Queue[AuditRecord]] = set()

    def append(self, record: AuditRecord) -> None:
        self._records.appendleft(record)
        for queue in tuple(self._subscribers):
            queue.put_nowait(record)

    def new_audit_id(self) -> str:
        return str(uuid4())

    def query(self, agent_id: str | None = None, decision: Decision | None = None, limit: int = 100) -> list[AuditRecord]:
        output: list[AuditRecord] = []
        for record in self._records:
            if agent_id and record.action.agent_id != agent_id:
                continue
            if decision and record.decision != decision:
                continue
            output.append(record)
            if len(output) >= limit:
                break
        return output

    async def stream(self) -> AsyncGenerator[AuditRecord, None]:
        queue: asyncio.Queue[AuditRecord] = asyncio.Queue()
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)
