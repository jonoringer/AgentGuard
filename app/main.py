from __future__ import annotations

import os
import time

from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse

from .audit import AuditStore
from .engine import PolicyEngine
from .models import AgentAction, AuditRecord, Decision, EvaluationResponse
from .policy import load_policy
from .telemetry import create_telemetry


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard",
        version="0.1.0",
        description="Policy firewall and audit layer for autonomous AI agents",
    )

    policy_path = os.getenv("AGENTGUARD_POLICY", "config/default_policy.json")
    audit_db_path = os.getenv("AGENTGUARD_AUDIT_DB", "agentguard_audit.db")
    enable_otel = os.getenv("AGENTGUARD_ENABLE_OTEL", "0").lower() in {"1", "true", "yes"}
    policy = load_policy(policy_path)
    engine = PolicyEngine(policy)
    audit = AuditStore(db_path=audit_db_path)
    telemetry = create_telemetry(enable_otel=enable_otel)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/guard/evaluate", response_model=EvaluationResponse)
    def evaluate(action: AgentAction) -> EvaluationResponse:
        started = time.perf_counter()
        with telemetry.evaluate_span(action.agent_id, action.tool):
            decision, enforcement_action, risk_score, confidence, reasons, rule_results = engine.evaluate(action)
        elapsed_ms = (time.perf_counter() - started) * 1000
        telemetry.record_decision(
            decision=decision.value,
            enforcement_action=enforcement_action.value,
            risk_score=risk_score,
            elapsed_ms=elapsed_ms,
        )
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
