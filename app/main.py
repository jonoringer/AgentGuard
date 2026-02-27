from __future__ import annotations

import os

from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse

from .audit import AuditStore
from .engine import PolicyEngine
from .models import AgentAction, AuditRecord, Decision, EvaluationResponse
from .policy import load_policy


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard",
        version="0.1.0",
        description="Policy firewall and audit layer for autonomous AI agents",
    )

    policy_path = os.getenv("AGENTGUARD_POLICY", "config/default_policy.json")
    policy = load_policy(policy_path)
    engine = PolicyEngine(policy)
    audit = AuditStore()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/guard/evaluate", response_model=EvaluationResponse)
    def evaluate(action: AgentAction) -> EvaluationResponse:
        decision, enforcement_action, risk_score, confidence, reasons, rule_results = engine.evaluate(action)
        audit_id = audit.new_audit_id()
        audit_record = AuditRecord(
            audit_id=audit_id,
            action=action,
            decision=decision,
            enforcement_action=enforcement_action,
            risk_score=risk_score,
            confidence=confidence,
            reasons=reasons,
            rule_results=rule_results,
        )
        audit.append(audit_record)
        return EvaluationResponse(
            decision=decision,
            enforcement_action=enforcement_action,
            risk_score=risk_score,
            confidence=confidence,
            reasons=reasons,
            rule_results=rule_results,
            audit_id=audit_id,
        )

    @app.get("/v1/audit/logs", response_model=list[AuditRecord])
    def list_logs(
        agent_id: str | None = Query(default=None),
        decision: Decision | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[AuditRecord]:
        return audit.query(agent_id=agent_id, decision=decision, limit=limit)

    @app.get("/v1/audit/stream")
    async def stream_logs() -> StreamingResponse:
        async def event_stream():
            async for record in audit.stream():
                payload = record.model_dump_json()
                yield f"event: audit\ndata: {payload}\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return app


app = create_app()
